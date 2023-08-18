import argparse
import sys


def load_certs(cert_file):
    with open(cert_file) as f:
        lines = f.readlines()
        template_start = -1
        template_end = 0
        templates = []

        for i in range(len(lines) - 1):
            line = lines[i]
            if "  Template[" in line and template_start >= 0:
                template_end = i
                templates.append(''.join(lines[template_start:template_end]))
                template_start = -1

            if "  Template[" in line:
                template_start = i

        return templates


def check_for_vulnerable_templates(templates):
    vulnerable_templates = []
    for template in templates:
        if "Client Authentication" in template and "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT" in template and "CTPRIVATEKEY_FLAG_EXPORTABLE_KEY" in template:
            vulnerable_templates.append(template)

    return vulnerable_templates


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path')
    args = parser.parse_args()
    templates = load_certs(args.path)
    list_of_vulnerable_templates = check_for_vulnerable_templates(templates)
    template_names = [i.split('\n')[0] for i in list_of_vulnerable_templates]
    if len(list_of_vulnerable_templates) < 1:
        print("No vulnerable templates found!")
        sys.exit(1)
    vulnerable_templates = '\n'.join(list_of_vulnerable_templates)
    print(f"{len(list_of_vulnerable_templates)} Vulnerable templates found:\n{vulnerable_templates}")
    sys.exit(0)
