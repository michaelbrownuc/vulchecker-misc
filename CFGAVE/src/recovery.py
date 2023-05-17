###############################################################################
# DARPA AIMEE - CFGAVE: Sample recovery code
# Author: Michael D. Brown
# Copyright Georgia Tech Research Institute, 2020
###############################################################################

# Standard library imports
import argparse
import json
import pathlib

# Third party imports
import networkx as nx
import yaml

# Local imports
from BB_node import *
import util


ATTRIBUTES = ['entry_addr', 'num_inst', 'trans_inst', 'arith_inst', 'call_inst', 'offspring', 'betweenness']


def split_filename(args):
    args.filename = args.yaml.parent.name
    args.function_name = args.yaml.name[len(args.filename) + 1:]


def function_name_label(args):
    return args.function_name


def juliet_label(args):
    if 'omitgood' in args.filename and 'bad' in args.function_name:
        return 'bad'
    else:
        return 'good'


def _main():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--label-mode', choices=['function-name', 'juliet'], default='function-name')
    parser.add_argument('yaml', help='YAML file to recover function ACFG from.', type=pathlib.Path)
    args = parser.parse_args()
    split_filename(args)

    if args.label_mode == 'function-name':
        label = function_name_label(args)
    elif args.label_mode == 'juliet':
        label = juliet_label(args)
    else:
        raise RuntimeError("Unreachable!")

    # Recover Network from YAML
    with open(args.yaml) as f:
        G = yaml.load(f, Loader=yaml.UnsafeLoader)

    # Calculate Betweeness of graph
    betweenness = nx.betweenness_centrality(G)

    new_graph = type(G)(label=label, filename=args.filename, function=args.function_name)
    node_lookup = {}
    for i, node in enumerate(G):
        node_lookup[node] = i
        new_graph.add_node(i, **dict(zip(ATTRIBUTES, node.get_attribute_vector(betweenness.get(node, 0)))))
    for u, v in G.edges:
        new_graph.add_edge(node_lookup[u], node_lookup[v])
    print(json.dumps(nx.node_link_data(new_graph)))


if __name__ == '__main__':
    _main()
