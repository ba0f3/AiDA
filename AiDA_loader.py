# AiDA_loader.py

from AiDA.plugin import PLUGIN_ENTRY as aida_plugin_entry

def PLUGIN_ENTRY():
  """
  IDA's entry point for the loader script, This needs to be in the plugin directory, OUTSIDE the AiDA directory.
  """
  return aida_plugin_entry()