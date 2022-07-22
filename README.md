# Manual steps required

### 1) Update local kubeconfig file
```
aws eks update-kubeconfig --name ExampleSystems-internal
```

### 2) Create Weekly and Monthly Data Lifecycle Policies (verify execution-role-arn)
```
aws dlm create-lifecycle-policy --execution-role-arn arn:aws:iam::308527748318:role/EksDLMLifecycleRole --description "EKS Weekly DLM lifecycle policy" --state "ENABLED" --policy-details file://conf/weekly-dlm-policy-details.json --tags "Name=EKS Weekly Backup"

aws dlm create-lifecycle-policy --execution-role-arn arn:aws:iam::308527748318:role/EksDLMLifecycleRole --description "EKS Monthly DLM lifecycle policy" --state "ENABLED" --policy-details file://conf/monthly-dlm-policy-detail.json --tags "Name=EKS Monthly Backup"
```