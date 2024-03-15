package cmd

import (
	"context"
	"io"
	"os"
	"path"
	"time"

	"github.com/zeropsio/zcli/src/archiveClient"
	"github.com/zeropsio/zcli/src/cmd/scope"
	"github.com/zeropsio/zcli/src/cmdBuilder"
	"github.com/zeropsio/zcli/src/httpClient"
	"github.com/zeropsio/zcli/src/i18n"
	"github.com/zeropsio/zcli/src/uxBlock/styles"
	"github.com/zeropsio/zcli/src/uxHelpers"
	"github.com/zeropsio/zerops-go/dto/input/body"
	dtoPath "github.com/zeropsio/zerops-go/dto/input/path"
	"github.com/zeropsio/zerops-go/types"
)

func servicePushCmd() *cmdBuilder.Cmd {
	return cmdBuilder.NewCmd().
		Use("push").
		Short(i18n.T(i18n.CmdPushDesc)).
		Long(i18n.T(i18n.CmdPushDesc)+"\n\n"+i18n.T(i18n.PushDescLong)).
		ScopeLevel(scope.Service).
		StringFlag("workingDir", "./", i18n.T(i18n.BuildWorkingDir)).
		StringFlag("archiveFilePath", "", i18n.T(i18n.BuildArchiveFilePath)).
		StringFlag("versionName", "", i18n.T(i18n.BuildVersionName)).
		StringFlag("source", "", i18n.T(i18n.SourceName)).
		StringFlag("zeropsYamlPath", "", i18n.T(i18n.ZeropsYamlLocation)).
		BoolFlag("deployGitFolder", false, i18n.T(i18n.UploadGitFolder)).
		HelpFlag(i18n.T(i18n.ServicePushHelp)).
		LoggedUserRunFunc(func(ctx context.Context, cmdData *cmdBuilder.LoggedUserCmdData) error {
			uxBlocks := cmdData.UxBlocks

			arch := archiveClient.New(archiveClient.Config{
				DeployGitFolder: cmdData.Params.GetBool("deployGitFolder"),
			})

			uxBlocks.PrintInfo(styles.InfoLine(i18n.T(i18n.BuildDeployCreatingPackageStart)))

			configContent, err := getValidConfigContent(
				uxBlocks,
				cmdData.Params.GetString("workingDir"),
				cmdData.Params.GetString("zeropsYamlPath"),
			)
			if err != nil {
				return err
			}

			err = validateZeropsYamlContent(ctx, cmdData.RestApiClient, cmdData.Service, configContent)
			if err != nil {
				return err
			}

			appVersion, err := createAppVersion(
				ctx,
				cmdData.RestApiClient,
				cmdData.Service,
				cmdData.Params.GetString("versionName"),
			)
			if err != nil {
				return err
			}

			err = uxHelpers.ProcessCheckWithSpinner(
				ctx,
				cmdData.UxBlocks,
				[]uxHelpers.Process{{
					F: func(ctx context.Context) (err error) {
						var size int64
						var reader io.Reader

						if cmdData.Params.GetString("archiveFilePath") != "" {
							packageFile, err := openPackageFile(
								cmdData.Params.GetString("archiveFilePath"),
								cmdData.Params.GetString("workingDir"),
							)
							if err != nil {
								return err
							}
							s, err := packageFile.Stat()
							if err != nil {
								return err
							}
							size = s.Size()
							reader = packageFile
						} else {
							tempFile := path.Join(os.TempDir(), appVersion.Id.Native())
							f, err := os.Create(tempFile)
							if err != nil {
								return err
							}
							defer os.Remove(tempFile)
							files, err := arch.FindGitFiles(cmdData.Params.GetString("workingDir"))
							if err != nil {
								return err
							}
							if err := arch.TarFiles(f, files); err != nil {
								return err
							}
							if err := f.Close(); err != nil {
								return err
							}
							readFile, err := os.Open(tempFile)
							if err != nil {
								return err
							}
							defer readFile.Close()
							stat, err := readFile.Stat()
							if err != nil {
								return err
							}
							size = stat.Size()
							reader = readFile
						}

						// TODO - janhajek merge with sdk client
						client := httpClient.New(ctx, httpClient.Config{
							HttpTimeout: time.Minute * 15,
						})
						if err := packageUpload(ctx, client, appVersion.UploadUrl.String(), reader, httpClient.ContentLength(size)); err != nil {
							// if an error occurred while packing the app, return that error
							return err
						}
						return nil
					},
					RunningMessage:      i18n.T(i18n.BuildDeployUploadingPackageStart),
					ErrorMessageMessage: i18n.T(i18n.BuildDeployUploadPackageFailed),
					SuccessMessage:      i18n.T(i18n.BuildDeployUploadingPackageDone),
				}},
			)
			if err != nil {
				return err
			}

			uxBlocks.PrintInfo(styles.InfoLine(i18n.T(i18n.BuildDeployCreatingPackageDone)))

			if cmdData.Params.GetString("archiveFilePath") != "" {
				uxBlocks.PrintInfo(styles.InfoLine(i18n.T(i18n.BuildDeployPackageSavedInto, cmdData.Params.GetString("archiveFilePath"))))
			}

			uxBlocks.PrintInfo(styles.InfoLine(i18n.T(i18n.BuildDeployDeployingStart)))

			sourceName := cmdData.Params.GetString("source")
			if sourceName == "" {
				sourceName = cmdData.Service.Name.String()
			}

			deployResponse, err := cmdData.RestApiClient.PutAppVersionBuildAndDeploy(ctx,
				dtoPath.AppVersionId{
					Id: appVersion.Id,
				},
				body.PutAppVersionBuildAndDeploy{
					ZeropsYaml: types.MediumText(configContent),
					Source:     types.NewStringNull(sourceName),
				},
			)
			if err != nil {
				return err
			}

			deployProcess, err := deployResponse.Output()
			if err != nil {
				return err
			}

			err = uxHelpers.ProcessCheckWithSpinner(
				ctx,
				cmdData.UxBlocks,
				[]uxHelpers.Process{{
					F:                   uxHelpers.CheckZeropsProcess(deployProcess.Id, cmdData.RestApiClient),
					RunningMessage:      i18n.T(i18n.PushRunning),
					ErrorMessageMessage: i18n.T(i18n.PushFailed),
					SuccessMessage:      i18n.T(i18n.PushFinished),
				}},
			)
			if err != nil {
				return err
			}

			return nil
		})
}
