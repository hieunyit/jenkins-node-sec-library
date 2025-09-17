package dockerfile

# Deny using an implicit latest tag or missing tag entirely.
deny[msg] {
  some i
  inst := input[i]
  lower(inst.instruction) == "from"
  base := split(trim_space(inst.value), " ")[0]
  not contains(base, ":")
  msg := sprintf("Base image '%s' must pin to a specific tag", [base])
}

deny[msg] {
  some i
  inst := input[i]
  lower(inst.instruction) == "from"
  base := split(trim_space(inst.value), " ")[0]
  endswith(lower(base), ":latest")
  msg := sprintf("Base image '%s' must not use the 'latest' tag", [base])
}

# Require a non-root user to be declared at the end of the Dockerfile.
deny[msg] {
  not declares_non_root_user
  msg := "Dockerfile must declare a non-root USER instruction"
}

declares_non_root_user {
  some i
  inst := input[i]
  lower(inst.instruction) == "user"
  user := lower(trim_space(inst.value))
  user != "root"
}

# Discourage use of ADD which can introduce remote fetches and archives.
deny[msg] {
  some i
  inst := input[i]
  lower(inst.instruction) == "add"
  msg := "Use COPY instead of ADD"
}

# Flag packages installed without a fixed version when using apk or apt-get.
deny[msg] {
  some i
  inst := input[i]
  lower(inst.instruction) == "run"
  re_match("(?i)apk add(?! .*\\-[^- ]*\\d)", inst.value)
  msg := "APK packages must be installed with a specific version"
}

deny[msg] {
  some i
  inst := input[i]
  lower(inst.instruction) == "run"
  re_match("(?i)apt(-get)? install(?! .*\\=[^ \\t]+)", inst.value)
  msg := "APT packages must be installed with a specific version"
}
