"""
Command-line interface for the Regorus SMT converter.
"""

import argparse
import sys
import json

from typing import Dict, Optional

from converter import RvmToSmtConverter


def load_program_from_file(filepath: str) -> Dict:
    """Load an RVM program from JSON file"""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"Error loading program from {filepath}: {e}")
        sys.exit(1)


def convert_program(args):
    """Convert an RVM program to SMT-LIB format"""
    print(f"Converting program from: {args.input}")
    
    # Load program
    program = load_program_from_file(args.input)
    
    
    converter = RvmToSmtConverter()
    # converter.set_verbose(args.verbose)
    
    # Convert to SMT
    smt_output = converter.convert_program(program)
    
    # Output result
    # if args.output:
    #    with open(args.output, 'w') as f:
    #        f.write(smt_output)
    #    print(f"SMT-LIB output written to: {args.output}")
    # else:
    #    print(smt_output)

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Regorus RVM to SMT Converter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s convert program.json -o output.smt2
        """)
    
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose output")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Convert command
    convert_parser = subparsers.add_parser("convert", help="Convert RVM program to SMT-LIB")
    convert_parser.add_argument("input", help="Input RVM program (JSON)")
    convert_parser.add_argument("--output", "-o", help="Output SMT-LIB file")
    convert_parser.set_defaults(func=convert_program)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Run the selected command
    args.func(args)


if __name__ == "__main__":
    main()
