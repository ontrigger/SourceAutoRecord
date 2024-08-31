#pragma once

#include <string>
#include "Utils/SDK.hpp"

namespace RngManip {
	void saveData(const char *filename);
	void loadData(const char *filename);

	void viewPunch(QAngle *offset);
	void randomSeed(int *seed);

	void init();

	void EnterProcessMovement(void *gamemovement, CMoveData *move);
	void ExitProcessMovement(CMoveData *move);
}
