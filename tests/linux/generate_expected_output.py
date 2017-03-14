#!/usr/bin/env python

import os
import sys
import json
import tempfile
import argparse
import shutil
import subprocess
import time
import base64


def b64(f):
    """ Base64 encodes the file 'f' """

    with open(f, 'r') as infile:
        return base64.b64encode(infile.read())

def run_a_program(pargs, outfile, errfile, timeout=600):

    with open(outfile, 'w') as outf:
        with open(errfile, 'w') as errf:
            sys.stdout.write("Executing: {}\n".format(pargs))
            po = subprocess.Popen(pargs, stderr=errf, stdout=outf)
            secs_used = 0

            while po.poll() is None and secs_used < timeout:
                time.sleep(1)
                secs_used += 1

    # took less than timeout
    if secs_used >= timeout:
        raise RuntimeError("A program ran for too long: {}".format(args))

    if po.returncode != 0:
        raise RuntimeError("A program returned an error code: {}".format(args))

def run_a_shell(shellargs, outfile, errfile):

    with open(outfile, 'w') as outf:
        with open(errfile, 'w') as errf:
            sys.stdout.write("Executing: {}\n".format(shellargs))
            try:
                subprocess.check_call(shellargs, stderr=errf, stdout=outf, shell=True)
            except subprocess.CalledProcessError as cpe:
                raise RuntimeError("A program returned an error code: {}".format(cpe.returncode))

def run_programs(testdir, basedir, rundict):
    # make new temp directory
    # read input json
    # run every test, redirect output to temp files

    output_dict = {}

    # look through every tested program
    for testname in rundict.iterkeys():
        # skip comments
        if testname.startswith("_"):
            continue

        sys.stdout.write("Processing test: {}\n".format(testname))
        # create a directory to store test outputs
        per_test_dir = os.path.join(testdir, testname)
        os.mkdir(per_test_dir)

        # build our output config dict
        output_config = output_dict.get(testname, {})

        configs = rundict[testname]
        for testconfig in configs.iterkeys():
            if testconfig.startswith("_"):
                continue

            if testconfig in output_config:
                raise RuntimeError("Already ran through configuration {} for test {}".format(testconfig, testname))

            sys.stdout.write("\tProcessing configuration: {}\n".format(testconfig))
            config = configs[testconfig]

            # only one test per config
            test_result = {}

            # prepare output files
            stdoutfile = os.path.join(per_test_dir, testname + ".stdout")
            stderrfile = os.path.join(per_test_dir, testname + ".stderr")

            prog = os.path.join(basedir, testname+".elf")
            if not os.path.exists(prog):
                raise RuntimeError("Could not find test program: {}".format(prog))
        
            if 'args' in config:
                progargs = [prog]
                progargs.extend(config['args'])

                # do the test
                run_a_program(progargs, stdoutfile, stderrfile)
            elif 'shell' in config:
                shellargs = config['shell']
                shellargs = shellargs.replace("#PROGNAME", prog)
                run_a_shell(shellargs, stdoutfile, stderrfile)
            else:
                raise RuntimeError("No 'args' or 'shell' item for test {}".format(testname))

            #base64 the output content to fit into json
            test_result['expected_stdout'] = b64(stdoutfile)
            test_result['expected_stderr'] = b64(stderrfile)

            # save output
            output_config[testconfig] = test_result

        output_dict[testname] = output_config

    # merge expected results with current config, so it can be saved as the ground truth json file
    for testname in output_dict.iterkeys():
        assert(testname in rundict)
        for config in output_dict[testname].iterkeys():
            assert(config in rundict[testname])
            for k, v in output_dict[testname][config].iteritems():
                # merge the test results dict into the json config
                rundict[testname][config][k] = v

    return rundict

def save_output(out_dict, outfile):
    # save it into JSON
    # clean up temp directory
    with open(outfile, 'w') as output_json:
        output_json.write(json.dumps(out_dict, indent=2, sort_keys=True))

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("jsonfile", help="JSON configuration file that says how to generate expected outputs")
    parser.add_argument("outfile", help="File of generated 'expected output' JSON")

    args = parser.parse_args()

    if not os.path.exists(args.jsonfile):
        sys.stderr.write("Could not find: {}\n".format(args.jsonfile))
        sys.exit(-1)

    basepath = os.path.dirname(os.path.realpath(args.jsonfile))

    with open(args.jsonfile, 'r') as jsonf:
        jdict = json.load(jsonf)

    tmpdir = tempfile.mkdtemp()
    sys.stdout.write("Using temporary directory: {}\n".format(tmpdir))
    outputs = run_programs(tmpdir, basepath, jdict)
    outputs['_autogenerated'] = "THIS IS AN AUTOGENERATED FILE. DO NOT EDIT."
    save_output(outputs, args.outfile)
    sys.stdout.write("Saved ground truth to: {}\n".format(args.outfile))
