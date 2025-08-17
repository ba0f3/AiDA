# AiDA Setup Instructions

## Environment Variables Required

Before building this project, you need to set up the following environment variable:

### IDASDK
Set this to point to your IDA SDK installation directory.

**Example:**
```
IDASDK=C:\path\to\your\idasdk91\idasdk91
```

**Setting up the IDASDK enviroment variable:**
1. Right-click "This PC" → Properties → Advanced System Settings 
2. Click "Environment Variables"
3. Under "User variables" or "System variables", click "New"
4. Variable name: `IDASDK`
5. Variable value: Your IDA SDK path

**After setting the IDASDK environment variable:**
1. Open your project in Visual Studio.
2. Go to Project Properties → Linker → General → Additional Library Directories.
3. Find where `ida.lib` is located in your SDK (usually `idasdk91\lib\x64_win_vc_64`).
4. Add the path to the Additional Library Directories field.

## Alternative Setup
If you prefer not to use environment variables, you can directly edit the paths in `AiDA\AiDA\AiDA.vcxproj` by replacing `$(IDASDK)` with your actual IDA SDK path.

## Build Requirements
- Visual Studio 2022
- IDA SDK 9.1 or compatible
- OpenSSL (installed in PATH)

## Building the Project
1. Open `AiDA\AiDA.sln` in Visual Studio 2022
2. Select the desired configuration (Debug x64 or Release x64)
3. Build the solution (Build → Build Solution or Ctrl+Shift+B)
4. The compiled DLL will be placed in `AiDA\x64\Release\` (for Release) or `AiDA\x64\Debug\` (for Debug)

## Installing the Plugin
After building, install the plugin:

1. Copy `AiDA\x64\Release\AiDA.dll` to `C:\Program Files\IDA Professional 9.1\plugins\`