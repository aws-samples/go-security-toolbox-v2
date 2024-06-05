# go-security-toolbox-v2

**Note** - uses the AWS go v2 SDK

This repo contains a collection of solutions that help customers maintain a high security posture in the cloud while also being easy to deploy.  


Available solutions below : 

- **CheckAccessNotGranted**

    Performs a scan of all IAM policies your aws account(s), checks to see if they contain any actions from the list of restriced actions and reports the findings to AWS Config and S3. 

    You specify the aws accounts, restricted actions and other attributes via a config file.  [More info here](./cmd/checkaccessnotgranted/README.md)
    
- **OrphanPolicyFinder** 

    Performs a scan of all IAM policieis in your aws account(s), checks to see if any are not attached to an IAM principals reports the findings to AWS Config and S3. 

    You specify the aws accounts and other attributes via a config file.  [More info here](./cmd/orphanpolicyfinder/README.md)