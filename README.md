> [!WARNING]
> Matilda is a prototype. Please report any issues and be mindful when using it in production.

# Matilda
Matilda provides sandboxing capabilities at runtime for the JVM. It is a lightweight alternative to the soon to be deprecated Java Security Manager. You can granuallary block modules from executing System.exit(), System.exec() and Network connections like Socket.open.
Matilda 

## Installation
Currently Matilda only supports JDK Version 23 or Higher as it heavily uses the(Class File API)[https://docs.oracle.com/en/java/javase/23/vm/class-file-api.html]. To use Matilda download the MatildaAgent.jar and the MatildaBootstrap.jar from the repository.


# Usage
Matilda can be used via the CLI or by configuring the projects build file accordingly. 

## CLI Quickstart
Enable preview features when using JDK 23 in order to be able to use the Class-File API
```bash
--enable-preview
```
Hook the MatildaAgent into your application
```bash
-javaagent:${project.rootDir}/build/libs/matilda-agent-1.0-SNAPSHOT.jar
```

Add the MatildaAcceControl to the bootpath. This is needed due to the class loading hirachy. Classes manipulated by the MatildaAgent reference to the MatildaAccessControl.
```bash
-Dmatilda.bootstrap.jar=${project.rootDir}/build/libs/matilda-bootstrap-1.0-SNAPSHOT.jar"
```
Note that Matilda works with a whitelisting approach. With enabling the MatildaAgent, all calls to the above mentioned methods will be blocked by default.

For gradle examples refer to the (Log4Shell example)[https://github.com/khaleesicodes/Matilda/blob/main/Log4Shell_Test/build.gradle]


## Configuration
Matilda comes with a module-based whitelisting approach, permission can be set per module and are enforced accordingly. If your projects does not use modules consider to change it, it is not only needed to use Matilda but also recommenede by the (Secure Coding Guidelines for Java SE)[https://www.oracle.com/java/technologies/javase/seccodeguide.html]

Configuration can also be done via the CLI or build file following the naming scheme:
```bash
-Dmatilda.system.exit.allow=module /<insert module name here/>
-Dmatilda.system.exec.allow=module /<insert module name here/>
-Dmatilda.network.connect.allow=module /<insert module name here/>
```




