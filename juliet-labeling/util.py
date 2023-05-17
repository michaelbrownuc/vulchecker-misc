import json
import os


def write_json(labels, output_dir, filename):
    """Write labels to JSON file.

    Keyword Arguments:
    labels -- The labels to write, should be JSON compatible
    output_dir -- Where to write the JSON file
    filename -- Name of the original src file
    """
    ofilepath = os.path.join(output_dir, filename + '.json')
    output_labels = []
    for line, label in labels.items():
        label_entry = {
            "filename": filename,
            "line_number": line,
            "label": label,
        }
        output_labels.append(label_entry)
    with open(ofilepath, 'w') as ofile:
        ofile.write(json.dumps(output_labels))
