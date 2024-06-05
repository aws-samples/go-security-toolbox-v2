package worker

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/s3api"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/sdkapimgr"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

type _CSVWorker struct {
	accountId    string              // account id to use when writing to s3
	records      [][]string          // records to write to csv
	buffer       *bytes.Buffer       // buffer for storing bytes
	csvWriter    *csv.Writer         // csv writer for writing to buffer
	outputConfig OutputConfiguration // output configuration for writing files to s3 or local filesystem
	Worker       Worker              // worker interface
}

type CsvWorkerConfig struct {
	AccountId    string       // account id to use when writing to s3
	WorkerConfig WorkerConfig // worker configuration
	OutputConfig OutputConfiguration
}

type OutputConfiguration struct {
	Headers    []string // headers for csv file
	Filename   string   // name of file to be written
	Prefix     string   // s3 prefix to use when writing to s3
	BucketName string   // name of s3 bucket
	WriteLocal bool     // write to local filesystem
	Writes3    bool     // write to s3
}

type CsvWorkerRequest struct {
	CsvRecord []string // string to write to csv file
}

// create new csv worker
func NewCSVWorker(config CsvWorkerConfig) (*_CSVWorker, error) {
	if !shared.IsValidAwsAccountId(config.AccountId) {
		log.Printf("invalid account id [%v]\n", config.AccountId)
		return nil, errors.New("invalid account id")
	}

	// check for valid ouptut configuration
	if !config.OutputConfig.WriteLocal && !config.OutputConfig.Writes3 {
		return nil, errors.New("invalid output configuration. writing to S3 & local file system set to false")
	}
	if config.OutputConfig.Writes3 && config.OutputConfig.BucketName == "" {
		return nil, errors.New("invalid output configuration. bucket name is empty")
	}
	if config.OutputConfig.Filename == "" {
		return nil, errors.New("invalid output configuration. filename is empty")
	}
	if len(config.OutputConfig.Headers) == 0 {
		return nil, errors.New("invalid output configuration. header is empty")
	}

	// create worker interface
	worker, err := NewWorker(config.WorkerConfig)
	// return errors
	if err != nil {
		return nil, errors.New("invalid worker config : " + err.Error())
	}

	records := [][]string{}            // initialize records to empty,
	buffer := new(bytes.Buffer)        // create new buffer
	csvWriter := csv.NewWriter(buffer) // create new csv writer that write to buffer

	// write headers to csv buffer
	if err := csvWriter.Write(config.OutputConfig.Headers); err != nil {
		return nil, err
	}

	csvWorker := &_CSVWorker{
		records:      records,
		buffer:       buffer,
		csvWriter:    csvWriter,
		accountId:    config.AccountId,
		outputConfig: config.OutputConfig,
		Worker:       worker,
	}

	worker.SetRequestHandler(csvWorker) // set csv worker request handler
	worker.SetFinalizer(csvWorker)

	return csvWorker, nil
}

// handle requests
func (csvWorker *_CSVWorker) Handle(request interface{}) {
	errorChan := csvWorker.Worker.GetErrorChannel()       // get error channel
	req := request.(CsvWorkerRequest)                     // type assert to csv worker request type
	record := req.CsvRecord                               // get record
	csvWorker.records = append(csvWorker.records, record) // append record to records
	// write record to buffer, send error to error channel if present
	if err := csvWorker.csvWriter.Write(record); err != nil {
		errorChan <- err // send error to error channel
	}
}

// finalize processing
func (csvWorker *_CSVWorker) Finalize() {
	errorChan := csvWorker.Worker.GetErrorChannel() // get error channel
	csvWriter := csvWorker.csvWriter                // get csv writer
	// flush csv writer
	csvWriter.Flush()

	// check for errors
	if err := csvWriter.Error(); err != nil {
		errorChan <- err // send error to error channel
	}
	finalBytes := csvWorker.buffer.Bytes() // get final bytes

	// write to local file system if specified in output configuration
	if csvWorker.outputConfig.WriteLocal {
		log.Printf("writing to file [%v]\n", csvWorker.outputConfig.Filename)
		file, err := os.Create(csvWorker.outputConfig.Filename)
		if err != nil {
			errorChan <- err // send error to error channel
			log.Printf("error creating file [%v]\n", err.Error())
		}
		defer file.Close()

		_, err = file.Write(finalBytes)
		if err != nil {
			errorChan <- err // send error to error channel
			log.Printf("error writing to file [%v]\n", err.Error())
		}
		log.Printf("finished writing to file [%v]\n", csvWorker.outputConfig.Filename)
	}

	// write to s3 if specified in output configuration
	if csvWorker.outputConfig.Writes3 {
		fullObjName := filepath.Join(csvWorker.outputConfig.Prefix, csvWorker.outputConfig.Filename)
		log.Printf("writing to s3 [%v]\n", fullObjName)

		awsClientMgr := csvWorker.Worker.GetSDKClientMgr() // get aws client manager
		client, _ := awsClientMgr.GetApi(csvWorker.accountId, sdkapimgr.S3Service)
		s3Client := client.(s3api.S3Api) // type assert to s3 sdk client
		_, err := s3Client.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: aws.String(csvWorker.outputConfig.BucketName),
			Key:    aws.String(fullObjName),
			Body:   bytes.NewReader(finalBytes),
		})
		if err != nil {
			errorChan <- err // send error to error channel
			log.Printf("error writing to s3 [%v]\n", err.Error())
		}
	}
}
