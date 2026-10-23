Reference cell-site library (bring your own lists)

Spoor does not ship any carrier's cell-site list. If you have them (CALEA / E911 tower lists from the
carriers' law-enforcement portals, a training set, your agency's share), put them here and Spoor will
use them to place call records whose return came without a tower list.

  1. Copy the lists into this folder, one sub-folder per carrier, named so the carrier is clear:
       cellsites\Verizon_Feb2025\...      cellsites\TMOB_Jan2025\...      cellsites\ATT_Feb2025\...
       cellsites\USCellular_Mar2025\...   cellsites\SprintLTE_Dec2021\...
     CSV, TXT, XLSX, XLS and ZIPs of them all work. A ZIP with a folder of the same name next to it
     is skipped (it has already been extracted).
  2. Index them (once, and again after adding lists - unchanged files are not re-read):
       spoor-cli.bat cellsites index
     The index is cellsites\cell_ref.db. Check it with:  spoor-cli.bat cellsites status
     Look up one cell:                                   spoor-cli.bat cellsites lookup 311480-0206D01

How it is used: a record is matched by LTE cell identity (ECI) to the list of the carrier its return
came from - taken from the case setting tel_carrier, else from the return's file name or folder. An ECI
is only unique within one carrier, so when the carrier is unknown a cell is placed only if every list
naming it agrees on the location. Every record placed this way cites the list file and row, and
REVIEW.md lists each list used with its SHA-256: check that the list's date covers the record dates.
Lists without ECIs (older CDMA lists) are used by cell label, and only when the carrier is known.

Turn it off for a case with the case setting tel_reference_library = false.
Nothing in this folder except this README is part of Spoor's source or its release package.
