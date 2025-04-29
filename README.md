# UAR (user access-rights review)

[![Build Status](https://drone.scaledome.io/api/badges/iam/uar/status.svg)](https://drone.scaledome.io/iam/uar)

## Presentation

This tool provides an authorizations assessment report for all users and resources of a given OUTSCALE account. 

## What does it do?

This program will issue oAPI Read calls to gather information on a given OUTSCALE account.

First, it builds an inventory of all resources for each resource type. 
Then it assesses applicable policies for each individual user accounts (including policies inherited from group membership).

It is possible to set optional filters on user-id and/or resource-id.

Assessment results are displayed on CLI screen and are stored in 3 report files named uar_report.csv, uar_report.json and uar_report.cypher  
It is possible to set a custom path and filename for these reports.

It is possible to specify a maximum value for how many resource instances should be displayed on screen in the CLI report.

## Installing on your workstation

You need Rust to compile UAR source code on your workstation.  
In case you don't have it already, you may install it by issuing this command line :

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Retrieve UAR source code from its public GitHub repository (you need to have GIT installed on your workstation to proceed successfully) :

```shell
git clone https://github.com/outscale/uar
```

Move to the repository folder :
```shell
cd uar
```

Update cargo (Rust's package manager) dependencies :
Move to the repository folder :
```shell
cargo update
```

Compile UAR program from the source code :
```shell
cargo build --release
```

Install compiled UAR program on your workstation :
```shell
cargo install --path .
```

## Usage

It is mandatory to specify these 3 arguments for this program to operate : access key, secret key, OSC public region. 
These arguments may either be set in the command line arguments (--osc-access-key, --osc-secret-key, --osc-region) or as environment variables ($OSC_ACCESS_KEY, $OSC_SECRET_KEY, $OSC_REGION).

Start the program by issuing this command line (you may need to add aforementioned mandatory arguments if they weren't set as environment variables) :

```shell
uar
```

You may set optional filters on user-id (TINA account ID or EIM username) and/or resource-id if you wish :

```shell
uar --osc-user-id Alice --osc-resource-id vol-493d8cd0
```

You may set the report path and filename if you wish (default value: 'uar_report') :

```shell
uar --report-path /report/my_report
```

You may set the maximum number of resource instances to display on CLI report if you wish (default value: '10') :

```shell
uar --max-resources-display-on-cli 3
```

## Warning on authorizations review
For a consistent access review, you shall use credentials from your OUTSCALE account or from an EIM user with extended read access (i.e. 'Allow api::Read*').  
Else you might get an empty or incomplete report.  
Obviously you also need Internet access for requests to OUTSCALE public API to complete successfully.  

**On authorizations:** this program will provide an exhaustive report of set policies.  
All statements in these policies are assessed by the authorization server before a decision is made about authorizing a given operation for a given user.  
You should keep in mind these 2 fundamental rules when reviewing authorization statements yourself:  
 1/ If an operation is not explicitly allowed in an authorization statement, it is implicitly denied ("implicit deny").  
 2/ If an operation is both allowed and denied by conflicting authorization statements, deny statement always prevails ("explicit allow < explicit deny").
