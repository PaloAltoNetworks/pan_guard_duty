# Integration between Palo Alto Network VM-Series FW with Amazon Guard Duty

The following sections describe the steps to be able to consume Amazon Guard Duty 
findings and subsequently apply security policy on the Palo Alto VM-Series Firewalls. 

0. Pre-Requisities 
   
   - Requires the use of the pandevice python package
   - Requires the use of the pan-python python package.

0.1 Make sure to enable the Guard Duty service on your AWS account.

1. git clone this repository.

2. In the same directory, install the pandevice and pan-python 
   packages as described below. 

   - From the git directory, change into the parent directory
   - pip install pandevice -t <directory which contains the code checked out from git>
   - pip install pan-python -t <directory which contains the code checked out from git>

3. Edit the "lambda_fw_config.py" file 
   - Update the Mgmt IP of the VM-Series FW and the username and password
     so that the lambda function can communicate with the FW. 

4. Create a zip file which contains the lambda code and the python packages. 

   - cd <directory which contains the code>
   - zip -r <filename>.zip . 

5. Create a bucket on S3
  
   - Create a folder named "lambda" in the bucket.

6. Upload the zip file to the S3 bucket

   - upload the zip file into the "lambda" folder
     of the bucket.

7. Make the changes in the cloud formation template 
   to reference the name of the S3 bucket created in step 4. 

   - Change the value of the "S3Bucket" key to be the name of the S3 bucket
     created in step 4.
   - Change the value of the "S3Key" key to be "lambda/<name of the zip file uploaded>"

8. Deploy the cloud formation template. 
