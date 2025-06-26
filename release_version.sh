#!/bin/bash

set -e

echo "Fetching latest tags from origin and synchronizing local tags..."

# 1. Удаляем локальные теги, соответствующие шаблону, чтобы избежать конфликтов
#    и учитывать только те, что есть в origin.
#    Ошибки игнорируются, если тегов нет.
LOCAL_TAGS_TO_DELETE=$(git tag -l "v*.*.*")
if [ -n "$LOCAL_TAGS_TO_DELETE" ]; then
  echo "Deleting local tags matching v*.*.* to resync with origin:"
  echo "$LOCAL_TAGS_TO_DELETE"
  git tag -d $LOCAL_TAGS_TO_DELETE 2>/dev/null || true
fi

# 2. Загружаем все теги из origin.
#    --prune-tags удалит локальные ссылки на теги, которых больше нет в origin
#    (требует Git 2.17+ и соответствующей настройки remote.<name>.tagOpt)
#    Более надежный способ - это комбинация удаления и fetch.
git fetch origin --tags --force # Получает все теги, обновляет существующие

# Теперь локальные теги "v*.*.*" должны соответствовать тем, что есть в origin
# (после предыдущего удаления и текущего fetch)

VERSION_ARG=$1

if [ -z "$VERSION_ARG" ]; then
  # Ищем последний тег vX.Y.Z локально (после синхронизации с origin)
  LATEST_TAG_FROM_ORIGIN=$(git tag -l "v*.*.*" --sort=-v:refname | head -n 1 2>/dev/null || echo "")
  
  echo "Latest semantic tag found (synchronized with origin): $LATEST_TAG_FROM_ORIGIN"

  if [ -z "$LATEST_TAG_FROM_ORIGIN" ]; then
    NEW_TAG="v0.1.0"
  else
    LATEST_TAG_NO_V=${LATEST_TAG_FROM_ORIGIN#v}
    IFS='.' read -r MAJOR MINOR PATCH <<< "$LATEST_TAG_NO_V"
    NEW_PATCH=$((PATCH + 1))
    NEW_TAG="v${MAJOR}.${MINOR}.${NEW_PATCH}"
  fi
  VERSION=$NEW_TAG
  echo "No version argument provided. Calculated new version: $VERSION"
else
  VERSION=$VERSION_ARG
  echo "Version argument provided: $VERSION"
fi

echo "Creating and pushing tag: $VERSION"
# Проверка, не существует ли уже такой тег локально (может быть, если аргумент был передан)
if git rev-parse "$VERSION" >/dev/null 2>&1; then
  echo "Tag $VERSION already exists locally. Attempting to push..."
else
  git tag "$VERSION"
fi
git push origin "$VERSION"

echo "Successfully processed tag $VERSION"
