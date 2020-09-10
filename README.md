# acm-ansible

This is an ansible module and playbook that I created to automate the puppet agent upgrade to v6, request certs from aws acm and do all the other things necessary. It's been sanitized of course.

It's used in our [AWX](https://github.com/ansible/awx) deployment so that it can be run on multiple hosts in a given role using our inventory.