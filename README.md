# AiDA - AI Assistant for IDA 9.0+

![Public](https://img.shields.io/badge/License-MIT-blue.svg)

AiDA is an AI-powered assistant plugin for IDA 9.0+, designed to accelerate the reverse engineering of modern C++ games. It leverages large language models (Gemini, OpenAI, Anthropic) to provide deep analysis, suggest names, generate C++ structures, and more, directly within the IDA environment.

## Features

*   (COMING SOON!) **Hybrid Engine Scanning:** Combines static pattern scanning (GSpots) and advanced AI analysis to locate critical Unreal Engine globals like `GWorld`, `GNames`, and `GObjects`.
*   **In-Depth Function Analysis:** Provides a detailed report on a function's purpose, logic, inputs/outputs, and potential game hacking opportunities.
*   **Automatic Renaming:** Suggests descriptive, context-aware names for functions.
*   **Struct Generation:** Reconstructs C++ structs from function disassembly, automatically handling padding and member offsets.
*   **Hook Generation:** Creates C++ MinHook snippets for easy function interception.
*   **Custom Queries:** Ask any question about a function and get a direct, technical answer.
*   **Multi-Provider Support:** Works with Google Gemini, OpenAI, and Anthropic models.

## Installation

1.  Ensure you have a compatible version of IDA (9.0+ recommended) and its associated Python 3 environment.
2.  Clone this repository or download it as a ZIP file.
3.  Copy the `AiDA` folder and the `AiDA_loader.py` file into your IDA plugins directory. The path is typically:
    *   `C:\Users\YOUR_USERNAME\AppData\Roaming\Hex-Rays\IDA Pro\plugins`
4.  Your plugins folder should look like this:
    ```
    ...
    C:.
    │   AiDA_loader.py
    │
    └───AiDA
        │   actions.py
        │   plugin.py
        │   ui.py
        │   __init__.py
        │
        ├───ai
        │   │   anthropic_client.py
        │   │   base_client.py
        │   │   gemini_client.py
        │   │   openai_client.py
        │   │   prompts.py
        │   │   __init__.py
        │
        ├───core
        │   │   ida_utils.py
        │   │   settings.py
        │   │   __init__.py
        │
        ├───patterns
        │       unreal.py
        │       __init__.py
    ...
    ```
5.  Install the required Python libraries for the AI provider you want to use. Open a command prompt and run the command for your IDA Python executable:
    ```cmd
    # For Gemini
    <path_to_ida_python> -m pip install google-generativeai

    # For OpenAI
    <path_to_ida_python> -m pip install openai

    # For Anthropic
    <path_to_ida_python> -m pip install anthropic

    However, if the commands above do not work, simply open cmd and 'pip install' without needing a path.
    ```

## Configuration

1.  The first time you run IDA with the plugin, it will prompt you to open the settings dialog.
2.  You can also access it via the right-click context menu in a disassembly view: `AI Assistant > Settings...`.
3.  In the settings, select your desired AI Provider and enter your API key. The key will be saved locally in your `ai_assistant.cfg` file and will not be uploaded to Git. (of course)

## Usage

Simply right-click within a disassembly or pseudocode view in IDA to access the `AI Assistant` context menu. From there, you can select any of the analysis or generation features.

## Important Note
Please be aware that AiDA is currently in **BETA** and is not yet fully stable. You may encounter bugs or unexpected behavior.
If you experience any issues or have bug reports, please reach out to "firewl" on Discord by sending a friend request, or by making a bug report on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.