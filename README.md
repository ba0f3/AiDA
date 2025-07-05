# AiDA - AI Assistant for IDA Pro

![License](https://img.shields.io/badge/License-MIT-blue.svg)

AiDA is a high-performance, AI-powered assistant plugin for IDA Pro (9.0+) written in C++ to provide maximum speed and stability. It's designed to accelerate the reverse engineering of modern C++ games by leveraging large language models (Google Gemini, OpenAI, and Anthropic) directly within the IDA environment.

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
    *   `%APPDATA%\Hex-Rays\IDA Pro\plugins` on Windows
    *   `$HOME/.idapro/plugins` on Linux/Mac

## Configuration

1.  The first time you run IDA Pro with the plugin, it will prompt you to open the settings dialog.
2.  You can also access it at any time via the right-click context menu in a disassembly or pseudocode view: `AI Assistant > Settings...`.
3.  In the settings dialog, select your desired AI Provider and enter your API key. The key will be saved locally in your user directory (`%APPDATA%\Hex-Rays\IDA Pro\ai_assistant.cfg`) and is never transmitted anywhere except to the AI provider's API.

### API Provider Configuration
*   **Provider:** Choose the AI service you want to use (Gemini, OpenAI, or Anthropic).
*   **API Key:** Your personal key for the selected provider. This is required for authentication.
*   **Model Name:** Specify which model to use. More powerful models (like GPT-4 Turbo or Claude 3 Opus) provide higher-quality analysis but cost more per use. Lighter models (like Gemini 1.5 Flash or GPT-4o mini) are faster and cheaper.

> **IMPORTANT: Model Choice Determines Output Quality**
> The quality of the AI model you select is the single most important factor affecting the accuracy and insightfulness of the results. For critical analysis of complex functions, using a top-tier model is **strongly recommended**.
>
> For example, a powerful model like **Google's Gemini 2.5 Pro** will consistently provide more comprehensive and correct analysis than a lighter, faster model like **Gemini 1.5 Flash**.

### Analysis Parameters
*   **Max Prompt Tokens:** This is a critical setting for managing cost and quality. It limits the total amount of context (your function's code, cross-references, etc.) sent to the AI.
    *   **Higher Value (e.g., 30,000):** Provides the AI with more context, leading to more accurate and detailed analysis. This is more expensive and slightly slower.
    *   **Lower Value (e.g., 8,000):** Cheaper and faster, but the AI may miss important details due to the limited context.

*   **XRef Context Count:** The maximum number of calling functions (callers) and called functions (callees) to include in the prompt. Increasing this gives the AI a better understanding of the function's role.

*   **XRef Analysis Depth:** How "deep" to go in the call chain when gathering context. A depth of `1` gets direct callers; a depth of `2` gets direct callers *and* their callers.
    > **Warning:** A depth greater than 3 can cause the context size to grow extremely quickly. However, a higher value is often necessary for a complete analysis of complex call chains.

*   **Code Snippet Lines:** The number of lines of decompiled code to include for each cross-reference. **A high value (e.g., 60-100) is recommended to give the AI better context.**

*   **Bulk Processing Delay:** A delay (in seconds) between consecutive API calls during automated tasks like the Unreal Scanner. This is a safety feature to prevent you from being rate-limited by the API provider.

## Usage

Simply right-click within a disassembly or pseudocode view in IDA to access the `AI Assistant` context menu. From there, you can select any of the analysis or generation features. All actions can also be found in the main menu under `Tools > AI Assistant`.

## Important Note
Please be aware that AiDA is currently in **BETA** and is not yet fully stable. You may encounter bugs or unexpected behavior.

If you experience any issues or have bug reports, please:
*   Create an issue on the [GitHub repository](https://github.com/sigwl/AiDA/issues).
*   Or, reach out to **"firewl"** on Discord by sending a friend request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.