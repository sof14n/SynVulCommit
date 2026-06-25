#!/usr/bin/env perl

@default_files = ("thesis");

# Use LuaLatex to create pdf
$pdflatex = 'lualatex -synctex=1 -interaction=nonstopmode';
$pdf_mode = 1;
$postscript_mode = $dvi_mode = 0;

# Use biber for bibliography
$biber = 'biber %O --bblencoding=utf8 -u -U --output_safechars %B';
$biber_silent_switch = '--onlylog';
push @generated_exts, 'bbl';
$clean_ext .= '%R.bbl';