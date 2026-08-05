#pragma once
#include "hp_common.h"

// Starts the control panel on port 80. Unlike v1 this runs for the whole life
// of the device, not only when Wi-Fi fails, so you can read the catch and
// change the bait while the trap is armed.
void webBegin();

// Services pending HTTP requests. Called from the web task.
void webPump();

// Reported on the dashboard so the operator knows where the device landed.
void webSetApFallback(bool active);
