This is an example to explore addressing and the PKO. It sends packets
from memory allocated in a number of different ways.

This is based on the passthrough example.

I have only used it with the simulator and only for Octeon II / CN68XX
configuration.

I use the oct-packet-io utility to capture the packets sent. The app
sends a fixed number of packets from each core; the number of cores is
configurable. All output goes out a single port. No output checking is
done, but you can look at the output file (output-2048.data, probably)
and verify that all the packets look the same.

To build and run the sample, make sure this repo is at

  OCTEON-SDK/examples/cavium-experiments

and make sure you've done

  $ source env-setup OCTEON_CN68XX

in the OCTEON-SDK directory. Then you can do

  $ cd OCTEON-SDK/examples/cavium-experiments
	$ make clean
	$ make
	$ make run

and you'll see the output scroll by. Page back to see the log messages
while sending packets. The sent packets will be captured in a file
probably called output-2048.data.

The number of processors simulated can be modified by changing
NUM_PROCESSORS in the makefile/command line ("make NUM_PROCESSORS=16").
