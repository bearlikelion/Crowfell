  # CROWFALL NOTES

  The full argument map from Launcher.Options:

  ┌─────────────┬───────────────────┬──────────────────────────────────────────┐
  │  Argument   │       Field       │                 Purpose                  │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -loginurl   │ OverrideLoginUrl  │ Directly sets auth server URL — use this │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -ecosystem  │ OverrideEcosystem │ Selects ecosystem from XML               │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -env        │ OverrideEnv       │ Environment override                     │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -username   │ Username          │ Pre-fill username                        │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -token      │ Token             │ Pre-fill token                           │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -procid     │ ProcessId         │ Process ID (from launcher)               │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -nographics │ NoGraphics        │ Headless mode                            │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -debug      │ —                 │ Debug mode                               │
  ├─────────────┼───────────────────┼──────────────────────────────────────────┤
  │ -logfile    │ LogFile           │ Log output path                          │
  └─────────────┴───────────────────┴──────────────────────────────────────────┘

  ┌────────────────────────────────────────────────┬────────────────────────────────────────┐
  │                    Function                    │ VA (paste into Ghidra "Go To Address") │
  ├────────────────────────────────────────────────┼────────────────────────────────────────┤
  │ JsonReader.Deserialize<CharacterListResponse> │ 0x1811F3930                            │
  ├────────────────────────────────────────────────┼────────────────────────────────────────┤
  │ PlayerManager.CharacterList.OnCharactersReceived │ 0x183282F60                         │
  ├────────────────────────────────────────────────┼────────────────────────────────────────┤
  │ StateLogin.CheckToken                          │ 0x183309B80                            │
  ├────────────────────────────────────────────────┼────────────────────────────────────────┤
  │ StateLogin.OnTransitionIn                      │ 0x18330AA70                            │
  ├────────────────────────────────────────────────┼────────────────────────────────────────┤
  │ StateAuthorizing.HandleLoginResponse           │ 0x183307BF0                            │
  ├────────────────────────────────────────────────┼────────────────────────────────────────┤
  │ StateAuthorizing.OnTransitionIn                │ 0x183307D00                            │
  ├────────────────────────────────────────────────┼────────────────────────────────────────┤
  │ StateEpicDataAuth.HandleAuthenticationResponse │ 0x183309500                            │
  └────────────────────────────────────────────────┴────────────────────────────────────────┘

  In HandleLoginResponse — look for the branch on success. If you patch the conditional jump so it always
  takes the success=true path, the client will proceed past auth regardless of server response.

  In CheckToken — look for what it does when the token string is empty/null. That's likely what triggers the
  re-login screen. Patching a null/empty check to always pass would let you launch the client with any token
  string.

  Character list:

  `dump.cs` shows the expected central-service payload is:

  ```json
  {
    "success": true,
    "message": "",
    "characters": [ /* CharacterEntry[] */ ]
  }
  ```

  The live failure in the client logs is:

  `InvalidCastException: Unable to cast object of type 'Object' to type 'CharacterListResponse'`

  That exception is thrown inside `JsonReader.Deserialize<CharacterListResponse>`, before
  `OnCharactersReceived` can process the list normally. The existing Ghidra script
  `ghidra_scripts/PatchCharacterListDeserialize.java` is meant to patch the IL2CPP-generated
  generic wrapper so it skips the bad klass-pointer comparison and takes the unbox/success path.
