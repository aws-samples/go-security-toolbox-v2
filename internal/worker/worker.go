package worker

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
)

type Worker interface {
	// wait for worker to finish
	Wait()
	// start processing request with the worker
	Run()
	// set request handler for the worker
	SetRequestHandler(WorkerRequestHandler)
	// set finalizer for the worker
	SetFinalizer(WorkerFinalizer)
	// get sdk client mgr
	GetSDKClientMgr() sdkapimgr.SdkApiMgr
	// get id of worker
	GetId() string
	// get error channel
	GetErrorChannel() chan error
	// get wait group
	GetWaitGroup() *sync.WaitGroup
	// check if request handler is set
	IsRequestHandlerSet() bool
	// check if finalizer is set
	IsFinalizerSet() bool
}

type WorkerRequestHandler interface {
	// method each worker will invoke when processing a request.  Each worker type will implement their own version
	// of this method.
	Handle(request interface{})
}

type WorkerFinalizer interface {
	// method each worker will invoke after they have completed all request.  This method is for any cleaup activites
	// or final actions a worker needs to take prior to shutdown
	Finalize()
}

type _Worker struct {
	ctx            context.Context      // execution context
	id             string               // id of worker
	wg             *sync.WaitGroup      // wait group for worker
	requestChan    chan interface{}     // request channnel for worker
	errorChan      chan error           // error channel for worker
	requestHandler WorkerRequestHandler // function to invoke when processing requests
	finalizer      WorkerFinalizer      // function to invoke when completed processing all requests
	sdkapimgr      sdkapimgr.SdkApiMgr  // manages sdk clients for processing
}

type WorkerConfig struct {
	Ctx          context.Context
	Id           string
	Wg           *sync.WaitGroup
	RequestChan  chan interface{}
	ErrorChan    chan error
	SdkClientMgr sdkapimgr.SdkApiMgr
}

func NewWorker(config WorkerConfig) (Worker, error) {

	// check for nil values in config
	if config.Ctx == nil {
		config.Ctx = context.Background() // set default context if nil
		log.Println("context is nil, setting to empty background context")
	}

	if config.Id == "" {
		return nil, errors.New("id is required")
	}
	if config.Wg == nil {
		return nil, errors.New("wg is required")
	}
	if config.RequestChan == nil {
		return nil, errors.New("request channel is required")
	}
	if config.ErrorChan == nil {
		return nil, errors.New("error channel is required")
	}
	if config.SdkClientMgr == nil {
		return nil, errors.New("sdk client manager is required")
	}

	worker := &_Worker{
		ctx:         config.Ctx,
		id:          config.Id,
		wg:          config.Wg,
		requestChan: config.RequestChan,
		errorChan:   config.ErrorChan,
		sdkapimgr:   config.SdkClientMgr,
	}

	worker.wg.Add(1) // increment wait group for worker
	go worker.Run()  // start worker in go routine
	log.Printf("worker [%v] started\n", worker.id)

	return worker, nil
}

// start processing request with the worker
func (w *_Worker) Run() {
	defer w.wg.Done()
	for request := range w.requestChan {
		w.requestHandler.Handle(request) // process requests from request channel
	}
	log.Printf("worker [%v] finished processing requests from buffer\n", w.id)
	if w.finalizer != nil {
		log.Printf("worker [%v] invoking finalizer\n", w.id)
		w.finalizer.Finalize() // finalize worker after processing all requests
	}
	log.Printf("worker [%v] exiting...\n", w.id)
}

// set request handler for the worker
func (w *_Worker) SetRequestHandler(requestHandler WorkerRequestHandler) {
	w.requestHandler = requestHandler
}

// set finalizer for the worker
func (w *_Worker) SetFinalizer(finalizer WorkerFinalizer) {
	w.finalizer = finalizer
}

// get sdk client mgr
func (w *_Worker) GetSDKClientMgr() sdkapimgr.SdkApiMgr {
	return w.sdkapimgr
}

// get id
func (w *_Worker) GetId() string {
	return w.id
}

// get error channel
func (w *_Worker) GetErrorChannel() chan error {
	return w.errorChan
}

// check if request handler is set
func (w *_Worker) IsRequestHandlerSet() bool {
	return w.requestHandler != nil
}

// check if finalizer is set
func (w *_Worker) IsFinalizerSet() bool {
	return w.finalizer != nil
}

// get wait group
func (w *_Worker) GetWaitGroup() *sync.WaitGroup {
	return w.wg
}

// wait for worker
func (w *_Worker) Wait() {
	w.wg.Wait()
}
