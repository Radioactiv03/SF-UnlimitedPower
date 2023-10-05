/* 
 * https://github.com/Starfield-Reverse-Engineering/CommonLibSF
 * This plugin template links against CommonLibSF
 */

#include "DKUtil/Hook.hpp"

namespace
{
	RE::ConsoleLog* console;

	/*
	static DWORD ThreadProc_OnDelayLoad(void* unused)
	{
		(void)unused;
		while (!RE::TESForm::LookupByID(0x14)) // Wait until forms are loaded, then run startup commands
		{
			Sleep(1000);
		}
		console = RE::ConsoleLog::GetSingleton();

		return 0;
	}
	*/
	void Install()
	{
		
		void* addr = dku::Hook::Assembly::search_pattern<
		"C5 ?? ?? ?? ?? "
		"48 8B ?? ?? "
		"C6 ?? ?? ?? ?? "
		"48 8B ?? ?? ?? "
		"C5 ?? ?? ?? ?? ?? "
		"48 83 ?? ?? "
		"5F C3 ?? ?? "
		"48 89">();
		
		int t = *(int*)addr;
		t = 0x90;
		
	}

	void MessageCallback(SFSE::MessagingInterface::Message* a_msg) noexcept
	{
		switch (a_msg->type) {
		case SFSE::MessagingInterface::kPostLoad:
			{
				
				//CreateThread(NULL, 4096, ThreadProc_OnDelayLoad, NULL, 0, NULL);
				Install();
			}
			break;
		default:
			break;
		}
	}
}

/**
// for preload plugins
void SFSEPlugin_Preload(SFSE::LoadInterface* a_sfse);
/**/

DLLEXPORT bool SFSEAPI SFSEPlugin_Load(const SFSE::LoadInterface* a_sfse)
{
#ifndef NDEBUG
	MessageBoxA(NULL, "Loaded. You can now attach the debugger or continue execution.", Plugin::NAME.data(), NULL);
#endif

	SFSE::Init(a_sfse, false);
	DKUtil::Logger::Init(Plugin::NAME, std::to_string(Plugin::Version));
	INFO("{} v{} loaded", Plugin::NAME, Plugin::Version);

	// do stuff
	// this allocates 1024 bytes for development builds, you can
	// adjust the value accordingly with the log result for release builds
	//SFSE::AllocTrampoline(1 << 10);
	//auto sig = "C5????????488B????C6????????488B??????C5??????????4883????5FC3????4889"; //,0x0,0x248,0x40,0xC0


	SFSE::GetMessagingInterface()->RegisterListener(MessageCallback);
	return true;
}
