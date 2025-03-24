#!/bin/bash

case "$1" in
  "start")
    docker-compose up -d
    echo "WordPress is starting at http://localhost:8000"
    echo "Please wait a few moments for the services to fully start..."
    echo "Once ready, visit http://localhost:8000 to complete WordPress installation"
    ;;
    
  "stop")
    docker-compose down
    echo "Environment stopped"
    ;;
    
  "logs")
    docker-compose logs -f
    ;;
    
  "clean")
    docker-compose down -v
    echo "Environment cleaned (all data removed)"
    ;;
    
  "restart")
    docker-compose restart
    echo "Environment restarted"
    ;;

  "wp")
    shift
    docker-compose exec wordpress wp "$@"
    ;;
    
  *)
    echo "Usage: $0 {start|stop|logs|clean|restart|wp}"
    echo ""
    echo "Commands:"
    echo "  start   - Start WordPress environment"
    echo "  stop    - Stop the environment"
    echo "  logs    - View logs"
    echo "  clean   - Remove all data and start fresh"
    echo "  restart - Restart the environment"
    echo "  wp      - Run WP-CLI commands inside WordPress container"
    exit 1
    ;;
esac