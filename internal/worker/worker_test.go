package worker

import (
	"log"
	"sync"
	"testing"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/stretchr/testify/assert"
)

type testWorker struct {
	worker Worker
}

func (t *testWorker) Handle(request interface{}) {
	log.Printf("test worker working on request [%v]", request)
}
func (t *testWorker) Finalize() {
	log.Println("test worker finalized")
}
func NewTestWorker(config WorkerConfig) (*testWorker, error) {
	worker, err := NewWorker(config)
	if err != nil {
		return nil, err
	}

	tw := &testWorker{
		worker: worker,
	}

	worker.SetRequestHandler(tw)
	worker.SetFinalizer(tw)

	return tw, nil
}

func TestNewWorker(t *testing.T) {
	assertion := assert.New(t)

	config := WorkerConfig{
		Ctx:          nil,
		Id:           "",
		Wg:           nil,
		RequestChan:  nil,
		ErrorChan:    nil,
		SdkClientMgr: nil,
	}

	// should throw error due to invalid id
	worker, err := NewWorker(config)
	assertion.Error(err)
	assertion.Nil(worker)

	// should throw error due to invalid wait group
	config.Id = "1" // make id valid
	worker, err = NewWorker(config)
	assertion.Error(err)
	assertion.Nil(worker)

	// should throw error due to invalid request channel
	config.Wg = new(sync.WaitGroup) // make wait group valid
	worker, err = NewWorker(config)
	assertion.Error(err)
	assertion.Nil(worker)

	// should throw error due to invalid error channel
	config.RequestChan = make(chan interface{}, 1) // make request channel valid
	worker, err = NewWorker(config)
	assertion.Error(err)
	assertion.Nil(worker)

	// should throw error due to invalid aws client manager
	config.ErrorChan = make(chan error, 1) // make error channel valid
	worker, err = NewWorker(config)
	assertion.Error(err)
	assertion.Nil(worker)

	// should not throw error
	awscm := sdkapimgr.NewAwsApiMgr()
	config.SdkClientMgr = awscm // make sdk client mgr valid
	worker, err = NewWorker(config)
	assertion.NoError(err)
	assertion.NotNil(worker)

	assertion.IsType(sdkapimgr.NewAwsApiMgr(), worker.GetSDKClientMgr())
	assertion.IsType(make(chan error, 1), worker.GetErrorChannel())
	assertion.Equal("1", worker.GetId())

	testWorker, err := NewTestWorker(config)
	assertion.NoError(err)
	assertion.NotNil(testWorker)

	close(config.RequestChan) // close request channel
	config.Wg.Wait()          // wait for worker to finish
	close(config.ErrorChan)   // close error channel

}

func TestWorkerRun(t *testing.T) {
	assertion := assert.New(t)

	requestChan := make(chan interface{}, 1) // make request channel
	errorChan := make(chan error, 1)         // make error channel
	wg := new(sync.WaitGroup)
	awscm := sdkapimgr.NewAwsApiMgr()
	config := WorkerConfig{
		Ctx:          nil,
		Id:           "1",
		Wg:           wg,
		RequestChan:  requestChan,
		ErrorChan:    errorChan,
		SdkClientMgr: awscm,
	}

	testWorker, err := NewTestWorker(config)
	assertion.NoError(err)
	assertion.NotNil(testWorker)

	assertion.True(testWorker.worker.IsRequestHandlerSet())
	requestChan <- "test" // send request to worker

	close(requestChan)
	wg.Wait() // wait for worker to finish
	close(errorChan)
}
