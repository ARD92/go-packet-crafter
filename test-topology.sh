#--------------------------------- #
# This is to create a simple 
# topology to test the application 
# on macOS
# -------------------------------- #
create()
{
    docker run -itd --privileged --name go1 -v ${PWD}:/app go-packet-crafter:v1.0
    docker run -itd --privileged --name go2 -v ${PWD}:/app go-packet-crafter:v1.0
    docker network create -d bridge go1_go2
    docker network connect go1_go2 go1
    docker network connect go1_go2 go2
}
destroy()
{
    docker stop go1 go2
    docker rm go1 go2
    docker network rm go1_go2
}
case $1 in 
import*)
    import
    ;;
create*)
    create
    ;;
destroy*)
    destroy
    ;;
*)
    echo "Invalid arg"
    ;;
esac

