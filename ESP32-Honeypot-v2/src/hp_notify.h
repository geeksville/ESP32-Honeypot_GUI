#pragma once
#include "hp_common.h"

// Starts the delivery worker. Alerts are posted from this task alone, so a
// slow or unreachable webhook can never stall the honeypot itself.
void notifyBegin();

// Non-blocking. Drops the event if the queue is full rather than waiting.
void notifyQueue(const Event& e);

// Sends a hand-made event so the operator can prove the destination works.
// Returns false with a reason if delivery fails.
bool notifyTest(String& err);

uint32_t notifySentCount();
uint32_t notifyFailCount();
uint32_t notifyDroppedCount();
