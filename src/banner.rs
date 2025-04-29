pub(crate) fn print_banner() -> () {
    let banner = r#"
                                                                                                    
        @@@@@@@
            @@
          @@
        @   @@@@@@@
   @@@@@@@   @@          @@@@@@   @@     @@ @@@@@@@@  @@@@@@@@  @@@@@@@  @@@@@@*   @@      @@@@@@@@
     @   @@   @@@      @@     @@  @@    @@     @@    @@@      @@        @@    @@  @@       @@
   @@   @@      @@    @@      @@ @@     @@    @@        @@@@ @@@       @@@@@@@@@  @@      @@@@@@@
  @@  @@@  @@@@@@@     @@@@@@@   @@@@@@@@     @@    @@@@@@@@  @@@@@@@  @@     @@ @@@@@@@  @@@@@@@@
 @@@@@
 
                                               @@@@@
                                             @@@@@@@@@
                                           @@@@@@@@@@@@@
                                          @@@@@@@  @@@@@@
                                      @   @@@@       @@@@   @
                                    @@@   @@@@       @@@@   @@@
                                 @@@@@@   @@@@       @@@@   @@@@
                               @@@@@@@    @@@@       @@@@   @@@@@   @
                            @@@@@@@@      @@@@       @@@@   @@@@@  @@@@
                            @@@@@@@@      @@@@       @@@@   @@@@@@@@@@@@
                            @@@ @@@@      @@@@       @@@@   @@@@@@@@@@@@
                                @@@@      @@@@@@@@@@@@@@@   @@@@@@@@@@@@
                                @@@@      @@@@@@@@@@@@@@@   @@@@@@@@@@@@
                                @@@@      @@@@@@@@@@@@@@@   @@@@ @@ @@@@
                                @@@@      @@@@       @@@@   @@@@    @@@@
                            @@@ @@@@      @@@@       @@@@   @@@@    @@@@
                            @@@@@@@@      @@@@       @@@@   @@@@    @@@@
                            @@@@@@@@@     @@@@       @@@@   @@@@    @@@
                               @@@@@@@@   @@@@       @@@@   @@@@    @
                                  @@@@@   @@@@       @@@@   @@@@
                                     @@   @@@@       @@@@   @@@
                                          @@@@       @@@@
                                           @@@       @@@

Warning: for a consistent access review, you shall use credentials from your Root account or from an EIM user with extended read access (i.e. 'Allow api::Read*').
Else you might get an empty or incomplete report.
Obviously you also need Internet access for requests to Outscale public API to complete successfully.

On authorizations: this program will provide an exhaustive report of set policies.
All statements in these policies are assessed by the authorization server before a decision is made about authorizing a given operation for a given user. 
You should keep in mind these 2 fundamental rules when reviewing authorization statements yourself:
 1/ If an operation is not explicitly allowed in an authorization statement, it is implicitly denied ("implicit deny").
 2/ If an operation is both allowed and denied by conflicting authorization statements, deny statement always prevails ("explicit allow < explicit deny"). 

Analysis in progress, it might take a while..

    "#;
    println!("{}", banner);
}
