# `pb-conceal` — put a value on the macOS pasteboard WITHOUT it being recorded.
#
# Reads the value on STDIN (never argv: `ps -eo args` shows argv to the same
# user) and writes it as a pasteboard item carrying two markers that `pbcopy`
# is structurally incapable of setting — `man pbcopy` offers only -help and
# -pboard, with no way to name a type:
#
#   org.nspasteboard.ConcealedType
#     The nspasteboard.org convention for "do not record me". 1Password and
#     Bitwarden SET it; Maccy, Alfred, Raycast and Paste HONOUR it. Maccy's
#     ignoredTypes contains it by default and un-switchably — user prefs can
#     only ADD captured types — and it is checked BEFORE the data is read.
#     Measured: a concealed write leaves 0 rows in Maccy's store where a
#     pbcopy of the same value leaves several.
#
#   NSPasteboardContentsCurrentHostOnly (prepareForNewContentsWithOptions:1)
#     The only documented opt-out from Universal Clipboard / Handoff, so the
#     value does not leave this Mac. Apple: the general pasteboard
#     "automatically participates with the Universal Clipboard feature" and
#     "there is no macOS API for interacting with this feature" — this option
#     is the exception.
#
# WHY JXA rather than a compiled helper: `osascript` ships with macOS, so the
# custom part is ~15 lines of JavaScript with no new dependency, no compiler
# and no build-time toolchain. A Swift helper would need the Swift toolchain
# available inside the Nix build sandbox, which on darwin is not dependable.
#
# UPSTREAM-FIRST (checked 2026-09-06): grepped the pinned home-manager,
# nix-darwin and nixpkgs for ConcealedType|nspasteboard|NSPasteboard|pbcopy|
# pasteboard|clipboard — ZERO files provide a concealed pasteboard write.
# home-manager's clipboard modules (services.clipcat, services.clipmenu,
# services.wl-clip-persist) are all Linux/X11/Wayland; nix-darwin has none;
# nixpkgs' clipboard CLIs (copyq, clipboard-jh, xclip, wl-clipboard, clipse)
# do not know the type — clipboard-jh's binary has 0 hits for it. So: custom.
#
# RESIDUAL RISK, stated plainly: any process can still read the pasteboard
# with no permission prompt, and that is not fixable from here. What this buys
# is a bounded, unrecorded window instead of a permanent record.
#
# This is deliberately a SEPARATE binary from the `secret` CLI: it knows
# nothing about the Keychain, takes any value on stdin, and is therefore the
# clean seam if it ever earns its own flake. Today it has one consumer
# (`secret copy`), which is why it has not been extracted.
{
  writeShellApplication,
  coreutils,
}:
writeShellApplication {
  name = "pb-conceal";
  runtimeInputs = [ coreutils ];
  text = ''
    usage() {
      printf '%s\n' \
        "usage: pb-conceal [--clear SECONDS]   (value is read from STDIN)" \
        "  Puts stdin on the macOS pasteboard marked concealed and host-only:" \
        "  clipboard-history tools skip it, and Universal Clipboard does not" \
        "  carry it off this Mac. Prints a status line, never the value." \
        "" \
        "  --clear N   clear the pasteboard after N seconds, but only if" \
        "              nothing else has copied since (changeCount unchanged)." \
        "              Mirrors pass(1)'s PASSWORD_STORE_CLIP_TIME." >&2
    }

    clear_after=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --clear)
          clear_after="''${2:-}"
          if [ -z "$clear_after" ]; then
            echo "pb-conceal: --clear needs SECONDS." >&2
            exit 1
          fi
          shift 2
          ;;
        -h | --help)
          usage
          exit 0
          ;;
        *)
          echo "pb-conceal: unknown argument '$1'" >&2
          usage
          exit 1
          ;;
      esac
    done
    if [ -n "$clear_after" ] && ! printf '%s' "$clear_after" | grep -qE '^[0-9]+$'; then
      echo "pb-conceal: --clear SECONDS must be a whole number." >&2
      exit 1
    fi
    if [ -t 0 ]; then
      echo "pb-conceal: refusing to read a value from a terminal — pipe it in." >&2
      exit 1
    fi

    # shellcheck disable=SC2016  # this is JavaScript: $(...) is the ObjC bridge, not shell
    cc="$(/usr/bin/osascript -l JavaScript -e '
      ObjC.import("AppKit");
      const d   = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
      const val = $.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding);
      const pb  = $.NSPasteboard.generalPasteboard;
      pb.prepareForNewContentsWithOptions(1);
      const it  = $.NSPasteboardItem.alloc.init;
      it.setStringForType(val, $.NSPasteboardTypeString);
      it.setStringForType($(""), $("org.nspasteboard.ConcealedType"));
      pb.writeObjects($.NSArray.arrayWithObject(it));
      String(pb.changeCount)
    ' 2>/dev/null)"
    if [ -z "$cc" ]; then
      echo "pb-conceal: pasteboard write failed" >&2
      exit 1
    fi

    if [ -n "$clear_after" ]; then
      ( sleep "$clear_after"
        # shellcheck disable=SC2016  # JavaScript, not shell
        /usr/bin/osascript -l JavaScript -e '
          function run(argv) {
            ObjC.import("AppKit");
            const pb = $.NSPasteboard.generalPasteboard;
            if (String(pb.changeCount) === argv[0]) { pb.clearContents; }
            return "";
          }' "$cc" >/dev/null 2>&1 || true
      ) >/dev/null 2>&1 &
      echo "pb-conceal: on the pasteboard — concealed, host-only, clears in ''${clear_after}s."
    else
      echo "pb-conceal: on the pasteboard — concealed, host-only."
    fi
  '';
}
