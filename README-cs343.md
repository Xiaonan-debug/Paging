To build and run on moore:

Install X11 on your client (XQuartz on Mac)

client> ssh -Y you@moore

moore> [make sure you are running the bash shell]
moore> git clone [assignment]
moore> cd [assignment]
moore> make -j 8 isoimage
moore> ./run

