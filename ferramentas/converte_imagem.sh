#!/bin/bash

# Convert the image to the provided resolution keeping the best aspect ratio and quality
convert "$1" \
  -filter Lanczos \
  -resize $3x$4! \
  -colorspace sRGB \
  -strip \
  -sampling-factor 4:4:4 \
  -quality 85 \
  "$2"
