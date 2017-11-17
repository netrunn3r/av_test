{
	if (($0 !~ "fatal: Not a git") &&
		($0 !~ "Nokogiri was built") &&
		($0 !~ "No platform") &&
		($0 !~ "No Arch") &&
		($0 !~ "No encoder") &&
		($0 !~ "succeeded with size") &&
		($0 !~ /Found [0-9]* compatible encoders/) &&
		($0 !~ "Attempting to read payload from STDIN")) {
			print $0
	}
}
