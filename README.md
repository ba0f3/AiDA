# AiDA - AI Assistant for IDA Pro

![License](https://img.shields.io/badge/License-MIT-blue.svg)

AiDA is a high-performance, AI-powered assistant plugin for IDA Pro (9.0+) in C++ to provide maximum speed and stability. It's designed to accelerate the reverse engineering of modern C++ games by leveraging large language models (Google Gemini, OpenAI, and Anthropic) directly within the IDA environment.

## Features

*   **(COMING SOON!) Hybrid Engine Scanning:** Combines static pattern scanning (GSpots) and advanced AI analysis to locate critical Unreal Engine globals like `GWorld`, `GNames`, and `GObjects`.
*   **In-Depth Function Analysis:** Provides a detailed report on a function's purpose, logic, inputs/outputs, and potential game hacking opportunities.
*   **Automatic Renaming:** Suggests descriptive, context-aware names for functions.
*   **Struct Generation:** Reconstructs C++ structs from function disassembly, automatically handling padding and member offsets.
*   **Hook Generation:** Creates C++ MinHook snippets for easy function interception.
*   **Custom Queries:** Ask any question about a function and get a direct, technical answer.
*   **Multi-Provider Support:** Works with Google Gemini, OpenAI (ChatGPT), and Anthropic (Claude) models.
*   **Native Performance:** Written in C++ for a seamless and fast user experience with no Python dependency.

## Installation

1.  Go to the [**Releases**](https://github.com/sigwl/AiDA/releases) page of this repository.
2.  Download the latest release ZIP file (e.g., `AiDA_v1.1.zip`).
3.  Extract the archive. You will find an `AiDA.dll` file.
4.  Copy `AiDA.dll` into your IDA Pro plugins directory. The path is typically:
    *   %APPDATA%\Hex-Rays\IDA Pro\plugins on Windows
    *   $HOME/.idapro/plugins on Linux/Mac

## Configuration

1.  The first time you run IDA Pro with the plugin, it will prompt you to open the settings dialog.
2.  You can also access it at any time via the right-click context menu in a disassembly or pseudocode view: `AI Assistant > Settings...`.
3.  In the settings dialog, select your desired AI Provider and enter your API key. The key will be saved locally in your user directory (`%APPDATA%\Hex-Rays\IDA Pro\ai_assistant.cfg`) and is never transmitted anywhere except to the AI provider's API.

## Usage

Simply right-click within a disassembly or pseudocode view in IDA to access the `AI Assistant` context menu. From there, you can select any of the analysis or generation features. All actions can also be found in the main menu under `Tools > AI Assistant`.

## Important Note
Please be aware that AiDA is currently in **BETA** and is not yet fully stable. You may encounter bugs or unexpected behavior.
If you experience any issues or have bug reports, please reach out to "firewl" on Discord by sending a friend request, or by creating an issue on the GitHub repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.