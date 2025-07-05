#pragma once

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <regex>
#include <future>
#include <sstream>
#include <map>
#include <set>
#include <fstream>
#include <mutex>
#include <condition_variable>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <typeinf.hpp>
#include <xref.hpp>
#include <lines.hpp>
#include <diskio.hpp>
#include <hexrays.hpp>

// Not repeating myself
static inline bool is_word_char(char c)
{
    return qisalnum(c) || c == '_' || c == ':';
}

#include "settings.hpp"
#include "prompts.hpp"
#include "ai_client.hpp"
#include "ida_utils.hpp"
#include "ui.hpp"
#include "actions.hpp"
#include "aida.hpp"