#pragma once
#include "hp_common.h"

class Print;

enum ShellStage : uint8_t { SH_LOGIN, SH_PASSWORD, SH_SUDO, SH_PROMPT };

struct ShellSession {
  char     cwd[80];
  char     user[32];
  char     pendingUser[32];
  uint8_t  stage;
  uint16_t commands;
  bool     greeted;
};

void shellReset(ShellSession& s);

// Feeds one complete line to the session and writes the response to `out`.
// Returns false when the session should be closed (exit / too much input).
// `ip` is only used for attributing the events this raises.
bool shellFeedLine(ShellSession& s, const String& line, Print& out, uint32_t ip);

// Emits the login banner and first prompt.
void shellGreet(ShellSession& s, Print& out);

// The current prompt string, e.g. "admin@srv-fileshare:~$ ".
String shellPrompt(const ShellSession& s);
