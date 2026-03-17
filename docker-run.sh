#!/bin/bash

# IR-DEPI | Docker Run Script

set -e

echo "======================================"
echo "  IR-DEPI | Docker Deployment"
echo "======================================"
echo

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your API keys before continuing."
    exit 1
fi

echo "✅ .env file found"
echo

# Parse command line arguments
case "${1:-build}" in
    build)
        echo "🔨 Building Docker image..."
        docker-compose build
        echo "✅ Build complete!"
        ;;
    up)
        echo "🚀 Starting IR-DEPI container..."
        docker-compose up -d
        echo "✅ Container started!"
        echo "   View logs: docker-compose logs -f"
        echo "   Stop: docker-compose down"
        ;;
    down)
        echo "🛑 Stopping IR-DEPI container..."
        docker-compose down
        echo "✅ Container stopped!"
        ;;
    logs)
        echo "📋 Showing logs..."
        docker-compose logs -f
        ;;
    restart)
        echo "🔄 Restarting IR-DEPI container..."
        docker-compose restart
        echo "✅ Container restarted!"
        ;;
    shell)
        echo "🐚 Opening shell in container..."
        # Use sh instead of bash for Windows compatibility
        docker-compose exec ir-depi /bin/sh
        ;;
    test)
        echo "🧪 Running tests inside container..."
        docker-compose run --rm ir-depi python test_api_keys.py
        docker-compose run --rm ir-depi python test_threat_intel.py
        ;;
    *)
        echo "Usage: $0 {build|up|down|logs|restart|shell|test}"
        exit 1
        ;;
esac

echo
echo "======================================"