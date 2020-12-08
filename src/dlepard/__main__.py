import sys

from . import dleprouter

sys.stderr.write("{}\n".format(dleprouter.PROG_NAME))
dleprouter.main()
