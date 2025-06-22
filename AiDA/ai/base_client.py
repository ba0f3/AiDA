from abc import ABC, abstractmethod

class AIClientBase(ABC):
    """
    Abstract base class defining the interface for all AI clients.
    This ensures that the main plugin can switch between different AI providers
    (Gemini, OpenAI, etc.) without changing the core logic.
    """

    @abstractmethod
    def __init__(self, settings):
        """Initializes the client with the provided settings."""
        self.settings = settings
        self.model = None

    @abstractmethod
    def is_available(self):
        """Returns True if the client is configured and ready to use."""
        pass

    @abstractmethod
    def analyze_function(self, ea):
        """Analyzes a function and returns a detailed report."""
        pass

    @abstractmethod
    def suggest_name(self, ea):
        """Suggests a new name for a function."""
        pass

    @abstractmethod
    def generate_struct(self, ea):
        """Generates a C++ struct definition from a function's code."""
        pass

    @abstractmethod
    def generate_hook(self, ea):
        """Generates a C++ MinHook snippet for a function."""
        pass

    @abstractmethod
    def custom_query(self, ea, question):
        """Asks a custom question about a function."""
        pass

    @abstractmethod
    def locate_global_pointer(self, ea, target_name):
        """
        [Coming soon!!!] Locates a global pointer (like GWorld, GNames, GObjects) in a function
        """
        pass