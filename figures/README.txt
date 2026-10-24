FIGURES FOLDER

Architecture status: the current block diagram is an earlier revision and shows
one Arduino with a direct UART link. The confirmed project architecture uses
two Arduino motor-controller nodes on a shared RS-485 bus. Update the Draw.io
source and exported image together before treating this figure as current.

Keep editable diagram source files here, for example:
- block_diagram.drawio
- motor_controller_schematic (EasyEDA project/source)
- motor_controller_pcb (EasyEDA project/source)

LaTeX does not render Draw.io or EasyEDA project files directly. Export figures
to PDF or PNG in this folder. The template includes the exported image when it
has one of the expected names below.

Required project figures:
1. block_diagram.png (or .pdf/.jpg)
2. motor_controller_schematic.pdf (PNG fallback: motor_controller_schematic.png)
3. motor_controller_pcb.pdf (PNG fallback: motor_controller_pcb.png)

If you use another filename, update the matching image path in
sections/05_methodology.tex.

Recommended:
- Export the EasyEDA schematic as PDF: vector output keeps component labels, net names,
  and pin numbers sharp when zoomed or printed. Keep the EasyEDA source/project too.
- Export the PCB layout as PDF when it is a clean vector view; use a high-resolution
  PNG if the PDF export is unclear or if you need a rendered board view. Include useful
  copper/silkscreen views and the board outline, with text readable when printed.
- The schematic and PCB are separate figures. If each controller board is identical,
  state that the figure shows one board and note that it is used for both front and rear.
- Keep labels large enough to remain readable at 90–95% page width. Update the image
  paths in sections/05_methodology.tex if you choose different filenames.
