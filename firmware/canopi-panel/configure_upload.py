Import("env")

# PlatformIO espressif32 6.12 wraps program_esp image paths in two Tcl brace
# pairs for its 2022 OpenOCD package. Current OpenOCD expects one pair.
upload_flags = []
for flag in env.get("UPLOADERFLAGS", []):
    if isinstance(flag, str) and "program_esp" in flag:
        flag = flag.replace("{{", "{").replace("}}", "}")
    upload_flags.append(flag)
env.Replace(UPLOADERFLAGS=upload_flags)
