package core

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
)

type Pool[T, R any] struct {
	processor    Processor[T, R]
	errorHandler ErrorHandler
	workerCount  int
	timeout      *time.Duration
	logger       logger.Logger

	jobQueue   chan T
	resultChan chan R
	errorChan  chan error

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

type PoolConfig struct {
	WorkerCount *int
	BufferSize  int
	Timeout     *time.Duration
	Logger      logger.Logger
}

func getWorkerCount(config *int) int {
	if config != nil {
		return *config
	}
	if count := os.Getenv(WorkerCountEnvVar); count != "" {
		if parsed, err := strconv.Atoi(count); err == nil && parsed > 0 {
			return parsed
		}
	}
	return DefaultWorkerCount
}

func NewPool[T, R any](config PoolConfig, processor Processor[T, R], errorHandler ErrorHandler) *Pool[T, R] {
	workerCount := getWorkerCount(config.WorkerCount)
	bufferSize := config.BufferSize
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	if config.Logger == nil {
		config.Logger = logger.NewLogger()
	}

	return &Pool[T, R]{
		processor:    processor,
		errorHandler: errorHandler,
		workerCount:  workerCount,
		timeout:      config.Timeout,
		logger:       config.Logger,
		jobQueue:     make(chan T, bufferSize),
		resultChan:   make(chan R, bufferSize),
		errorChan:    make(chan error, bufferSize),
	}
}

func (p *Pool[T, R]) Start(ctx context.Context) {
	p.ctx, p.cancel = context.WithCancel(ctx)

	for i := 0; i < p.workerCount; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
	p.logger.Info("Started worker pool with %d workers", p.workerCount)
}

func (p *Pool[T, R]) worker(workerID int) {
	defer p.wg.Done()

	for {
		select {
		case job, ok := <-p.jobQueue:
			if !ok {
				return
			}

			ctx := p.ctx
			if p.timeout != nil {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, *p.timeout)
				defer cancel()
			}

			result, err := p.processor.Process(ctx, job)
			if err != nil {
				p.errorHandler.HandleError(ctx, err, job)
				p.errorChan <- err
			} else {
				p.resultChan <- result
			}

		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Pool[T, R]) Submit(job T) bool {
	select {
	case p.jobQueue <- job:
		return true
	default:
		p.logger.Warn("Job queue is full, dropping job")
		return false
	}
}

func (p *Pool[T, R]) Results() <-chan R {
	return p.resultChan
}

func (p *Pool[T, R]) Errors() <-chan error {
	return p.errorChan
}

func (p *Pool[T, R]) Stop() {
	close(p.jobQueue)
	p.wg.Wait()
	close(p.resultChan)
	close(p.errorChan)
	if p.cancel != nil {
		p.cancel()
	}
	p.logger.Info("Worker pool stopped")
}