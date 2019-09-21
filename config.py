import os
import toml

# Switch cwd to the dir this script is in, so config files etc. can be read
# easily with relative paths.
os.chdir(os.path.dirname(os.path.realpath(__file__)))

# Absolute paths should be used if changing this, unless the new file
# is placed in this dir.
CONFIG_FILE = 'config.toml'

# Make configuration settings globally available
conf = toml.load(CONFIG_FILE)
