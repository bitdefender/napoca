@echo off
REM This script allows customizing prebuild steps for each of the projects
REM Usage: Create a ProjectName_prebuild.cmd file for any project you need special prebuild logic
REM Arguments: pre|post buid|rebuild|clean ConfigurationName PlatformName DevEnvDir InputDir InputExt InputFileName InputName InputPath IntDir OutDir ParentName ProjectDir ProjectExt ProjectFileName ProjectName ProjectPath RemoteMachine SafeInputName SafeParentName SafeRootNamespace SolutionDir SolutionExt SolutionFileName SolutionName SolutionPath TargetDir TargetExt TargetFileName TargetFramework TargetName TargetPath VCInstallDir VSInstallDir WindowsSdkDir WindowsSdkDirIA64 PackageDir 

echo %~dp0\build_event_%~1.cmd %*
if exist %~dp0\build_event_%~1.cmd call %~dp0\build_event_%~1.cmd %*