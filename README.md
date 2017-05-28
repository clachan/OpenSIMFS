# OpenSIMFS
Open-source re-implementation of SIMFS.

Memory-Style Storage (MSS) is emerging as persistent memory technologies advance. By attaching the persistent memories directly to memory bus, we enjoy DRAM-like latency and storage-like persistency.

In 2016, we saw two outstanding research papers, SIMFS [1] and NOVA[2], both aiming at improving performance of the file system on persistem memories. NOVA maximizes performance on hybrid memory sytems while maintaing strong consistency guarantees. SIMFS brings the idea of "File Virtual Address Space" which leverages the existing address translation hardware (MMU). NOVA has its home on GitHub (https://github.com/Andiry/nova). Unfortunately, SIMFS has not been open-sourced yet.

The idea of OpenSIMFS is to re-implement the ideas from the paper and open-source to the public as a research tool. OpenSIMFS adopts the "File Virtual Address Space" from SIMFS and the consistency framrwork from NOVA.

[1] Designing an efficient persistent in-memory file system. http://ieeexplore.ieee.org/document/7304365
[2] NOVAL A Log-structured File System for Hybrid Volatile/Non-volatile Main Memories. https://www.usenix.org/conference/fast16/technical-sessions/presentation/xu
