This is an example to explore multi-segment sends with the PKO.

This is based on the passthrough example.

I have only used it with the simulator and only for Octeon II / CN68XX
configuration.

I use the oct-packet-io utility to capture the packets sent. The app
sends a fixed number of packets from each core; the number of cores is
configurable. All output goes out a single port. No output checking is
done, but you can look at the output file (output-2048.data, probably)
and verify that all the packets look the same.

Build and run the sample:

	$ make clean
	$ make
	$ make run

The number of processors simulated can be modified by changing
NUM_PROCESSORS in the makefile.
