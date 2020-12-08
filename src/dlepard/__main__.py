import sys

import dlepard.dleprouter

sys.stderr.write("{} {}\n".format(dlepard.__name__, dlepard.__version__))
dlepard.dleprouter.main()
