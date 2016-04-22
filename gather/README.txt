This is an example to explore multi-segment sends with the PKO.

This is based on the passthrough example.

I have only used it with the simulator and only for Octeon II / CN68XX
configuration.

I use the oct-packet-io utility to capture the packets sent. The app
sends a fixed number of packets from each core; the number of cores is
configurable. All output goes out a single port.

Output checking is done automatically when running on a single core.

To build and run the code, make sure this repo is at

  OCTEON-SDK/examples/cavium-experiments

and make sure you've done

  $ source env-setup OCTEON_CN68XX

in the OCTEON-SDK directory. Then you can do

  $ cd OCTEON-SDK/examples/cavium-experiments/gather
	$ make clean
	$ make
	$ make run

and you'll see the output scroll by. Page back to see the log messages
while sending packets. The sent packets will be captured in a file
probably called output-2048.data. With a single core, we should see
two packets: one from the gather-based approach and one from the
linked-list-based approach (and "make run" will verify them).

The number of processors simulated can be modified by changing
NUM_PROCESSORS in the makefile/command line ("make NUM_PROCESSORS=16").
