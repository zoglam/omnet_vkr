double startTime, endTime;

startTime = getCPUTime( );
...
endTime = getCPUTime( );

fprintf( stderr, "CPU time used = %lf\n", (endTime - startTime) );