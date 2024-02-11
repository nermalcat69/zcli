package i18n

var en = map[string]string{
	// help
	DisplayHelp:              "Displays help for ",
	GroupHelp:                "any command.",
	DeployHelp:               "the deploy command.",
	LogShowHelp:              "the log show command.",
	LoginHelp:                "the login command.",
	ProjectHelp:              "the project command.",
	ProjectStartHelp:         "the project start command.",
	ProjectStopHelp:          "the project stop command.",
	ProjectListHelp:          "the project list command.",
	ScopeHelp:                "the scope command.",
	ScopeProjectHelp:         "the scope project command.",
	ScopeServiceHelp:         "the scope project command.",
	ScopeResetHelp:           "the scope reset command.",
	ProjectDeleteHelp:        "the project delete command.",
	ProjectImportHelp:        "the project import command.",
	ProjectServiceImportHelp: "the project service import command.",
	ServiceHelp:              "the service command.",
	PushHelp:                 "the push command.",
	RegionListHelp:           "the region list command.",
	ServiceStartHelp:         "the service start command.",
	ServiceStopHelp:          "the service stop command.",
	ServiceImportHelp:        "the service import command.",
	ServiceDeleteHelp:        "the service delete command.",
	ServiceLogHelp:           "the service log command.",
	ServiceDeployHelp:        "the service deploy command.",
	ServiceListHelp:          "the service list command.",
	ServicePushHelp:          "the service push command.",
	StatusHelp:               "the status command.",
	StatusInfoHelp:           "the status info command.",
	StatusShowDebugLogsHelp:  "the status show debug logs command.",
	VersionHelp:              "the version command.",
	BucketCreateHelp:         "the bucket create command.",
	BucketDeleteHelp:         "the bucket delete command.",

	// cmd short
	CmdDeployDesc:          "Deploys your application to Zerops.",
	CmdPushDesc:            "Builds your application in Zerops and deploys it.",
	CmdLogin:               "Logs you into Zerops. Use a generated Zerops token or your login e-mail and password.",
	CmdStatus:              "Status commands group.",
	CmdStatusInfo:          "Shows the current status of the Zerops CLI.",
	CmdStatusShowDebugLogs: "Shows zCLI debug logs.",
	CmdVersion:             "Shows the current zCLI version.",
	CmdRegion:              "Zerops region commands group.",
	CmdRegionList:          "Lists all Zerops regions.",
	CmdProject:             "Project commands group.",
	CmdService:             "Zerops service commands group.",
	CmdProjectStart:        "Starts the project and the services that were running before the project was stopped.",
	CmdProjectStop:         "Stops the project and all of its services.",
	CmdProjectList:         "Lists all projects.",
	CmdScope:               "Scope commands group",
	CmdScopeProject:        "Sets the scope for project. All commands that require project ID will use the selected one.",
	CmdScopeService:        "Sets the scope for service. All commands that require service ID will use the selected one.",
	CmdScopeReset:          "Resets the scope for project and service.",
	CmdProjectDelete:       "Deletes a project and all of its services.",
	CmdProjectImport:       "Creates a new project with one or more services.",
	CmdServiceImport:       "Creates one or more Zerops services in an existing project.",
	CmdServiceStart:        "Starts the Zerops service.",
	CmdServiceStop:         "Stops the Zerops service.",
	CmdServiceDelete:       "Deletes the Zerops service.",
	CmdServiceLog:          "Get service runtime or build log to stdout.",
	CmdBucket:              "S3 storage management",
	CmdBucketZerops:        "Management via Zerops API",
	CmdBucketS3:            "Management directly via S3 API",
	CmdBucketCreate:        "Creates a bucket in an existing object storage.",
	CmdBucketDelete:        "Deletes a bucket from an existing object storage.",

	// cmd long
	CmdProjectImportLong: "Creates a new project with one or more services according to the definition in the import YAML file.",
	DeployDescLong:       "pathToFileOrDir defines a path to one or more directories and/or files relative to the working\ndirectory. The working directory is by default the current directory and can be changed\nusing the --workingDir flag. zCLI deploys selected directories and/or files to Zerops.",
	PushDescLong:         "The command triggers the build pipeline defined in zerops.yml. Zerops.yml must be in the working\ndirectory. The working directory is by default the current directory and can be changed\nusing the --workingDir flag. zCLI uploads all files and subdirectories of the working\ndirectory to Zerops and starts the build pipeline. Files found in the .gitignore\nfile will be ignored.\n\nIf you just want to deploy your application to Zerops, use the zcli deploy command instead.",
	CmdServiceLogLong:    "Returns service runtime or build log to stdout. By default, the command returns the last 100\nlog messages from all service runtime containers and exits.\n",
	ServiceLogAdditional: "\nUse the <serviceName> alone in the command to return log messages from all runtime containers.\nSet <serviceName>@1 to return log messages from the first runtime container only.\nSet <serviceName>@build to return log messages from the last build if available.",

	// flags description
	RegionFlag:            "Choose one of Zerops regions. Use the \"zcli region list\" command to list all Zerops regions.",
	RegionUrlFlag:         "Zerops region file url.",
	BuildVersionName:      "Adds a custom version name. Automatically filled if the VERSIONNAME environment variable exists.",
	SourceName:            "Override zerops.yml service name.",
	BuildWorkingDir:       "Sets a custom working directory. Default working directory is the current directory.",
	BuildArchiveFilePath:  "If set, zCLI creates a tar.gz archive with the application code in the required path relative\nto the working directory. By default, no archive is created.",
	ZeropsYamlLocation:    "Sets a custom path to the zerops.yml file relative to the working directory. By default zCLI\nlooks for zerops.yml in the working directory.",
	UploadGitFolder:       "If set, zCLI the .git folder is also uploaded. By default, the .git folder is ignored.",
	OrgIdFlag:             "If you have access to more than one organization, you must specify the org ID for which the\nproject is to be created.",
	LogLimitFlag:          "How many of the most recent log messages will be returned. Allowed interval is <1;1000>.\nDefault value = 100.",
	LogMinSeverityFlag:    "Returns log messages with requested or higher severity. Set either severity number in the interval\n<0;7> or one of following severity codes:\nEMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG.",
	LogMsgTypeFlag:        "Select either APPLICATION or WEBSERVER log messages to be returned. Default value = APPLICATION.",
	LogShowBuildFlag:      "If set, zCLI will return build log messages instead of runtime log messages.",
	LogFollowFlag:         "If set, zCLI will continuously poll for new log messages. By default, the command will exit\nonce there are no more logs to display. To exit from this mode, use Control-C.",
	LogFormatFlag:         "The format of returned log messages. Following formats are supported: \nFULL: This is the default format. Messages will be returned in the complete Syslog format. \nSHORT: Returns only timestamp and log message.\nJSON: Messages will be returned as one JSON object.\nJSONSTREAM: Messages will be returned as stream of JSON objects.",
	LogFormatTemplateFlag: "Set a custom log format. Can be used only with --format=FULL.\nExample: --formatTemplate=\"{{.timestamp}} {{.severity}} {{.facility}} {{.message}}\".\nSupports standard GoLang template format and functions.",
	TerminalFlag:          "If enabled provides a rich UI to communicate with a user. Possible values: auto, enabled, disabled. Default value is auto.",
	LogFilePathFlag:       "Path to a log file. Default value: %s.",
	ConfirmFlag:           "If set, zCLI will not ask for confirmation of destructive operations.",
	ServiceIdFlag:         "If you have access to more than one service, you must specify the service ID for which the\ncommand is to be executed.",
	ProjectIdFlag:         "If you have access to more than one project, you must specify the project ID for which the\ncommand is to be executed.",

	// process
	ProcessInvalidState: "last command has finished with error, identifier for communication with our support: %s",

	// archiveClient
	ArchClientWorkingDirectory:  "working directory: %s",
	ArchClientMaxOneTilde:       "only one ~(tilde) is allowed",
	ArchClientPackingDirectory:  "packing directory: %s",
	ArchClientPackingFile:       "packing file: %s",
	ArchClientFileAlreadyExists: "file [%s] already exists",

	// login
	LoginSuccess: "You are logged as %s <%s>",

	// region
	RegionNotFound:        "Selected region %s not found",
	RegionTableColumnName: "Name",

	// import
	ImportYamlOk:        "Yaml file was checked",
	ImportYamlEmpty:     "Config file import yaml is empty",
	ImportYamlTooLarge:  "Max. size of import yaml is 100 KB",
	ImportYamlFound:     "Import yaml found",
	ImportYamlNotFound:  "Import yaml not found",
	ImportYamlCorrupted: "Import yaml corrupted",
	ServiceCount:        "Number of services to be added: %d",
	QueuedProcesses:     "Queued processes: %d",
	CoreServices:        "Core services activation started",

	// delete cmd
	DeleteCanceledByUser: "delete command canceled by user",

	// project + service
	ProjectDeleteConfirm: "Project %s will be deleted? \n Are you sure?",
	ServiceDeleteConfirm: "Service %s will be deleted? \n Are you sure?",
	ProjectStarting:      "Project is being started",
	ProjectStarted:       "Project was started",
	ProjectStopping:      "Project is begin stopped",
	ProjectStopped:       "Project was stopped",
	ProjectDeleting:      "Project is being deleted",
	ProjectDeleted:       "Project was deleted",
	ServiceStarting:      "Service is being started",
	ServiceStarted:       "Service was started",
	ServiceStopping:      "Service is being stopped",
	ServiceStopped:       "Service was stopped",
	ServiceDeleting:      "Service is being deleted",
	ServiceDeleted:       "Service was deleted",
	ProjectImported:      "project imported",
	ServiceImported:      "service(s) imported",

	// service logs
	LogLimitInvalid:              "Invalid --limit value. Allowed interval is <1;1000>",
	LogMinSeverityInvalid:        "Invalid --minimumSeverity value.",
	LogMinSeverityStringLimitErr: "Allowed values are EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG.",
	LogMinSeverityNumLimitErr:    "Allowed interval is <0;7>.",
	LogFormatInvalid:             "Invalid --format value. Allowed values are FULL, SHORT, JSON, JSONSTREAM.",
	LogFormatTemplateMismatch:    "--formatTemplate can be used only in combination with --format=FULL.",
	LogFormatStreamMismatch:      "--format=JSON cannot be used in combination with --follow. Use --format=JSONSTREAM instead.",
	LogServiceNameInvalid:        "Invalid serviceName value. Multiple @ characters are not supported. See -h for help.",
	LogFormatTemplateInvalid:     "Invalid --formatTemplate content. The custom template failed with following error:",
	LogFormatTemplateNoSpace:     "Template items must be split by a (single) space.",
	LogSuffixInvalid:             "Invalid serviceName value. Use <serviceName>@<int> to  return log messages from the N-th runtime container only.\nUse <serviceName>@BUILD to return log messages from the last build if available.",
	LogRuntimeOnly:               "This command can be used on runtime services only.",
	LogNoContainerFound:          "No runtime container was found.",
	LogTooFewContainers:          "There %s only %d runtime container%s at the moment. Select a lower container index.",
	LogNoBuildFound:              "No build was found for this service.",
	LogBuildStatusUploading:      "Service status UPLOADING, need to wait for app version data.",
	LogAccessFailed:              "Request for access to logs failed.",
	LogMsgTypeInvalid:            "Invalid --messageType value. Allowed values are APPLICATION, WEBSERVER.",
	LogReadingFailed:             "Log reading failed.",

	// push
	PushRunning:  "Push is running",
	PushFinished: "Push finished",

	// deploy
	DeployHintPush:                   "To build your application in Zerops, use the zcli push command instead.",
	BuildDeployCreatingPackageStart:  "creating package",
	BuildDeployCreatingPackageDone:   "package created",
	BuildDeployPackageSavedInto:      "package file saved into: %s",
	BuildDeployUploadingPackageStart: "uploading package",
	BuildDeployUploadingPackageDone:  "package uploaded",
	BuildDeployUploadPackageFailed:   "package upload failed",
	BuildDeployDeployingStart:        "deploying service",
	BuildDeployZeropsYamlEmpty:       "config file zerops.yml is empty",
	BuildDeployZeropsYamlTooLarge:    "max. size of zerops.yml is 10 KB",
	BuildDeployZeropsYamlFound:       "File zerops.yml found. Path: %s.",
	BuildDeployZeropsYamlNotFound:    "File zerops.yml not found. Expected path: %s.",

	// s3
	BucketGenericXAmzAcl:              "Defines one of predefined grants, known as canned ACLs.\nValid values are: private, public-read, public-read-write, authenticated-read.",
	BucketGenericXAmzAclInvalid:       "Invalid --x-amz-acl value. Allowed values are: private, public-read, public-read-write, authenticated-read.",
	BucketGenericOnlyForObjectStorage: "This command can be used on object storage services only.",
	BucketGenericBucketNamePrefixed:   "Bucket names are prefixed by object storage service ID to make the bucket names unique.\nLearn more about bucket naming conventions at https://docs.zerops.io/documentation/services/storage/s3.html#used-technology",

	BucketCreated:                 "Bucket created",
	BucketCreateCreatingDirect:    "Creating bucket %s directly on S3 API.",
	BucketCreateCreatingZeropsApi: "Creating bucket %s using Zerops API.",

	BucketDeleteConfirm:           "Bucket %s will be deleted? \n Are you sure?",
	BucketDeleted:                 "Bucket deleted",
	BucketDeleteDeletingDirect:    "Deleting bucket %s directly on S3 API.",
	BucketDeleteDeletingZeropsApi: "Deleting bucket %s using Zerops API.",

	BucketS3AccessKeyId:         "When using direct S3 API the accessKeyId to the Zerops object storage is required.\nAutomatically filled if the {serviceName}_accessKeyId environment variable exists.",
	BucketS3SecretAccessKey:     "When using direct S3 API the secretAccessKey to the Zerops object storage is required.\nAutomatically filled if the {serviceName}_secretAccessKey environment variable exists.",
	BucketS3FlagBothMandatory:   "If you are specifying accessKeyId or secretAccessKey, both flags are mandatory.",
	BucketS3EnvBothMandatory:    "If you are using env for accessKeyId or secretAccessKey, both env variables must be set.",
	BucketS3RequestFailed:       "S3 API request failed: %s",
	BucketS3BucketAlreadyExists: "The bucket name already exists under a different object storage user. Set a different bucket name.",

	// status info
	StatusInfoCliDataFilePath: "Zerops CLI data file path",
	StatusInfoLogFilePath:     "Zerops CLI log file path",

	// debug logs
	DebugLogsNotFound: "Debug logs not found",

	////////////
	// global //
	////////////

	// args
	ArgsOnlyOneOptionalAllowed: "optional arg %s can be only the last one",
	ArgsOnlyOneArrayAllowed:    "array arg %s can be only the last one",
	ArgsNotEnoughRequiredArgs:  "expected at least %d arg(s), got %d",
	ArgsTooManyArgs:            "expected no more than %d arg(s), got %d",

	// logger
	LoggerUnableToOpenLogFileWarning: "Failed to open a log file, used path: %s. Try to use --log-file-path flag.\n",

	// ux helpers
	ProjectSelectorListEmpty:       "You don't have any projects yet. Create a new project using `zcli project import` command.",
	ProjectSelectorPrompt:          "Please, select a project",
	ProjectSelectorOutOfRangeError: "We couldn't find a project with the index you entered. Please, try again or contact our support team.",
	ServiceSelectorListEmpty:       "Project doesn't have any services yet. Create a new service using `zcli service import` command",
	ServiceSelectorPrompt:          "Please, select a service",
	ServiceSelectorOutOfRangeError: "We couldn't find a service with the index you entered. Please, try again or contact our support team.",
	OrgSelectorListEmpty:           "You don't belong to any organization yet. Please, contact our support team.",
	OrgSelectorPrompt:              "Please, select an org",
	OrgSelectorOutOfRangeError:     "We couldn't find an org with the index you entered. Please, try again or contact our support team.",
	SelectorAllowedOnlyInTerminal:  "Interactive selection can be used only in terminal mode. Use command flags to specify missing parameters.",
	PromptAllowedOnlyInTerminal:    "Interactive prompt can be used only in terminal mode. Use --confirm=true flag to confirm it",

	UnauthenticatedUser: `unauthenticated user, login before proceeding with this command
zcli login {token}
more info: https://docs.zerops.io/documentation/cli/authorization.html`,

	// scope
	SelectedProject:         "Selected project: %s",
	SelectedService:         "Selected service: %s",
	ScopedProject:           "Scoped project: %s",
	ScopedProjectNotFound:   "Scoped project wasn't found, Select a different project using `zcli scope project` command.",
	PreviouslyScopedProject: "Previously scoped project: %s",
	ScopeReset:              "Scope was reset",

	DestructiveOperationConfirmationFailed: "You have to confirm a destructive operation.",
}
