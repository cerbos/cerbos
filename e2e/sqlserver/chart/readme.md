# Readme.md

This HELM chart is a sample "as-is" chart provided for reference to help guide with SQL Server deployment on Kubernetes cluster. 
 
## Prerequisites:
 
1.	This chart is built on helm v3. It requires a kubernetes cluster to be running for you to deploy SQL container using this chart. 
2.	Ensure you have the helm installed on the client from where you will connect to the kubernetes cluster to deploy using the helm chart.
3.	For minimum hardware requirement for the host to run SQL Server containers please refer to the system requirements section for SQL on Linux. 
4.	Requires the following variables to be set or changed in the values.yaml file :<br/> 
    a.  Please ensure that you accept the EULA for SQL Server, by changing the value of ACCEPT_EULA.value=y in values.yaml file or set it during the helm install command --set ACCEPT_EULA.value=Y.<br/> 
    b.	Please do choose the right edition of SQL Server that you would like to install you can change the value of the MSSQL_PID.value in the values file to the edition that you want to install or you can also 
        change it during the helm install command using the option --set MSSQL_PID.value=Enterprise, If you do not pass the flag and do not change it in the yaml, then by default it is going to install developer edition.<br/> c. Also please do provide your customized value for the sa_password, if you do not provide it then by default the sa_password will the value as shown in the below table.<br/> 
 
Note: Once you deploy SQL server containers using the chart below, please log into SQL Server using sa account and change the password as mentioned here, this ensures that as DBA you have the control of the sa user and password.  
 
  
## Chart usage:
 
On the client machine where you have the Helm tools installed, download the chart on your machine and make the required changes to the values.yaml file as per your requirement. To see the list of settings that can be changed using the values.yaml file please refer to the table below.
 
|     Configuration parameters                 |     Description                                                                                                                                                                  |     Default_Value                     |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------|
|     Values.image.repository                  |     The   SQL image to be downloaded and used for container deployment.                                                                                                          |     mcr.microsoft&#46;com/mssql/server   |
|     Values.image.tag                         |     The   tag of the image to be download for the specific SQL image.                                                                                                            |     2019-latest                       |
|     Values.ACCEPT_EULA.value                 |     Set   the ACCEPT_EULA variable to any value to confirm your acceptance of   the SQL Server EULA, please refer environment   variable  for more details.                      |     Y                                 |
|     Values.MSSQL_PID.value                   |     Set   the SQL Server edition or product key. please refer environment   variable  for more details                                                                           |     Developer                         |
|     Values.MSSQL_AGENT_ENABLED.value         |     Enable   SQL Server Agent. For example, 'true' is enabled and 'false' is disabled. By   default, agent is disabled. please refer environment   variable for more details.    |     TRUE                              |
|     Values.hostname                          |     The   name that you would like to see when you run the select @@servername for the   SQL instance running inside the container.                                              |     mssqllatest                       |
|     Values.sa_password                       |     Configure   the SA user password.                                                                                                                                            |     StrongPass1!                      |
|     Values.containers.ports.containerPort    |     Port   on which the SQL Server is listening inside the container.                                                                                                            |     1433                              |
|     Values.podSecurityContext.fsgroup        |     Security   context at the pod level.                                                                                                                                         |     10001                             |
|     Values.service.type                      |     The   type of the service to be created within the kubernetes cluster.                                                                                                       |     LoadBalancer                      |
|     Values.service.port                      |     The   service port number.                                                                                                                                                   |     1433                              |
|     Values.pvc.StorageClass                  |     The   storage class to be used by the kubernetes cluster for SQL Server deployment.                                                                                          |     azure-disk                        |
|     Values.pvc.userdbaccessMode              |     The   access mode for the pvc (persistance volume claim) to be used by user   databases.                                                                                     |     ReadWriteOnce                     |
|     Values.pvc.userdbsize                    |     The   size to allocate to the persistance volume claim (pvc).                                                                                                                |     5Gi                               |
|     Values.pvc.userlogaccessMode             |     The   access mode for the pvc (persistance volume claim) to be used by the log   files of the user databases.                                                                |     ReadWriteOnce                     |
|     Values.pvc.userlogsize                   |     The   size to allocate to the persistance volume claim (pvc) used by the log files   of the user databases.                                                                  |     5Gi                               |
|     Values.pvc.tempdbaccessMode              |     The   access mode for the pvc (persistance volume claim) to be used by temp   database.                                                                                      |     ReadWriteOnce                     |
|     Values.pvc.   Tempsize                   |     The   size to allocate to the persistance volume claim (pvc) used by the temp   database.                                                                                    |     2Gi                               |
|     Values.pvc.mssqldataaccessMode           |     The   access mode for the pvc (persistance volume claim) to be used by system   databases.                                                                                   |     ReadWriteOnce                     |
|     Values.pvc.mssqldbsize                   |     The   size to allocate to the  persistance   volume claim (pvc) used by the system databases                                                                                 |     2Gi                               |
 
 

## Deployment details:
 
> [!NOTE]
> Here are my deployment details, please make changes to the values.yaml or other files as per your requirement.
 
In this scenario, I am deploying SQL Server containers on a Azure Kubernetes Service (AKS). You can follow Setup and connect to AKS documentation to read instructions on setup and connections. Also the storage class that I am using here is "Azure-disk". Please do find details below for each of the yaml file used in the template folder of this chart.
 
| File Name | Description |
|-|-|
| _helpers.tpl | Template file with all the template definitions that will be used in this chart. |
| deployment.yaml | A manifest file to describing the deployment details for SQL Server. |
| mssqlconfig.yaml | SQL server   mssql.conf file and its content that you would like to mount to the SQL Server container. For parameters that you can pass in this file please refer mssql.conf documentation. To modify the mssql.conf settings please modify this file. |
| pvc.yaml | A manifest file that describes the storage class (SC), Persistent volume (PV) and Persistent volume claims (pvc). This will be mounted to the SQL Container and referenced by the deployment.yaml. To make any changes to the sc,pv or pvc please modify this file accordingly. |
| secret.yaml | A manifest file to create secrets to manage the sa_password that will be used to login to the SQL Server container that is deployed. Please modify the value.yaml file to provide your custom sa_password that you will use to login into the SQL Server once deployed. As a security measure please ensure that you change the sa_password once you login to the SQL Server for the first time. |
| service.yaml | A manifest file that defines the kubernetes service type and port. Please modify this for any service modification that is needed. |

With this information, and probably after you have modified the required files you are now ready to deploy SQL Server using this chart. From the client machine where you have the helm chart installed, change the 
directory of the CLI to the directory where you have the chart downloaded and to deploy SQL Server using this chart run the command:


``` bash 
helm install mssql-latest-deploy . --set ACCEPT_EULA.value=Y --set MSSQL_PID.value=Developer
```

 
After a few seconds this should deploy the SQL Server containers and you can see all the artifacts using the command :

```bash
D:\helm-charts\mssql-latest\mssql-latest>kubectl get all
```

The output should look as shown below:

```bash
NAME                                       READY   STATUS    RESTARTS   AGE
pod/mssql-latest-deploy-645c4dddd8-647zk   1/1     Running   4          23h

NAME                          TYPE           CLUSTER-IP   EXTERNAL-IP    PORT(S)          AGE
service/kubernetes            ClusterIP      10.0.0.1     <none>         443/TCP          140d
service/mssql-latest-deploy   LoadBalancer   10.0.57.19   20.44.43.212   1433:30544/TCP   23h

NAME                                  READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/mssql-latest-deploy   1/1     1            1           23h

NAME                                             DESIRED   CURRENT   READY   AGE
replicaset.apps/mssql-latest-deploy-645c4dddd8   1         1         1       23h
```

## Connect to SQL Server

Now you are ready to connect to the SQL Server using any of the familiar tools that you work with, like the [SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver15) (SQL Server Management Studio) or [SQLCMD](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver15) or [ADS](https://docs.microsoft.com/en-us/sql/azure-data-studio/download-azure-data-studio?view=sql-server-ver15) (Azure Data Studio), etc. The IP address that you will use to connect is the External-IP address for the mssql-latest-deploy service which in this case is 20.44.43.212 that will be used to connect to SQL Server.

For more details on the SQL Server deployment on AKS using manual method please refer [Deploy a SQL Server container in Kubernetes with Azure Kubernetes Services (AKS)](https://docs.microsoft.com/en-us/sql/linux/tutorial-sql-server-containers-kubernetes?view=sql-server-ver15).
